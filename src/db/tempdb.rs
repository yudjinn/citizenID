use aws_sdk_dynamodb::{
    config::Region,
    operation::create_table::CreateTableOutput,
    types::{
        AttributeDefinition, AttributeValue, KeySchemaElement, KeyType, ProvisionedThroughput,
        ScalarAttributeType,
    },
    Client,
};
use color_eyre::{Report, Result};
use serde::{Deserialize, Serialize};
use serde_dynamo::aws_sdk_dynamodb_0_33::{from_item, from_items, to_item};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::model::Model;

pub static LOCAL_DB: OnceCell<Client> = OnceCell::const_new();

pub async fn get_or_init() -> &'static Client {
    LOCAL_DB
        .get_or_init(|| async {
            let config = aws_config::from_env()
                .profile_name("localstack")
                .endpoint_url("http://localhost:8000")
                .region(Region::new("us-east-1"))
                .load()
                .await;
            Client::new(&config)
        })
        .await
}

pub async fn init_db() -> Result<()> {
    let client = get_or_init().await;
    // find out if the tables exist
    let resp = client.list_tables().send().await.unwrap();

    let names = resp.table_names().unwrap_or_default();
    println!("Found tables: {:?}", names);

    let reqs: Vec<String> = vec!["users".to_owned(), "applications".to_owned()];

    // make whatever is missing
    let l = reqs
        .iter()
        .filter(|&x| !names.contains(x))
        .cloned()
        .collect::<Vec<String>>();
    println!("Missing: {:?}", &l);

    for n in l {
        match create_table(&client, &n, "id").await {
            Ok(o) => {
                println!("Response:\n {:?}", o);
            }
            Err(e) => {
                println!("Error:\n {}", e);
            }
        }
    }

    Ok(())
}

pub async fn get_item_from_table_with_filter<T>(column_name: &str, value: &str) -> Result<Option<T>>
where
    T: for<'a> Model<'a> + Serialize + for<'a> Deserialize<'a> + Clone,
{
    let client = get_or_init().await;
    let result = client
        .query()
        .table_name(T::TABLE)
        .key_condition_expression(format!("#{} = :{}", column_name, column_name))
        .expression_attribute_names(column_name, column_name)
        .expression_attribute_values(
            format!(":{}", column_name),
            AttributeValue::N(value.to_owned()),
        )
        .send()
        .await?;

    if let Some(items) = result.items {
        let t: Vec<T> = from_items(items)?;
        let ret: T = t.get(0).unwrap().clone();
        Ok(Some(ret))
    } else {
        Ok(None)
    }
}

pub async fn put_item<T>(item: T) -> Result<T>
where
    T: for<'a> Model<'a> + Serialize + for<'a> Deserialize<'a> + Clone,
{
    let client = get_or_init().await;

    let i = to_item(item)?;

    let request = client.put_item().table_name(T::TABLE).set_item(Some(i));
    let resp = request.send().await?;

    let attrs = resp.attributes().unwrap();

    let obj: T = from_item(attrs.clone())?;

    Ok(obj)
}

pub async fn update_item<T>(id: Uuid, item: T) -> Result<T>
where
    T: for<'a> Model<'a> + Serialize + for<'a> Deserialize<'a> + Clone,
{
    if let Ok(Some(_)) = get_item_from_table_with_filter::<T>("id", &id.to_string()).await {
        let client = get_or_init().await;

        let i = to_item(item)?;

        let request = client.put_item().table_name(T::TABLE).set_item(Some(i));
        let resp = request.send().await?;

        let attrs = resp.attributes().unwrap();

        let obj: T = from_item(attrs.clone())?;

        Ok(obj)
    } else {
        Err(Report::msg(format!(
            "Item [{}]-{} was not found.",
            std::any::type_name::<T>(),
            id
        )))
    }
}
pub async fn create_table(client: &Client, table: &str, key: &str) -> Result<CreateTableOutput> {
    let a_name: String = key.into();
    let table_name: String = table.into();

    let ad = AttributeDefinition::builder()
        .attribute_name(&a_name)
        .attribute_type(ScalarAttributeType::S)
        .build();

    let ks = KeySchemaElement::builder()
        .attribute_name(&a_name)
        .key_type(KeyType::Hash)
        .build();

    let pt = ProvisionedThroughput::builder()
        .read_capacity_units(10)
        .write_capacity_units(5)
        .build();

    let create_table_response = client
        .create_table()
        .table_name(table_name)
        .key_schema(ks)
        .attribute_definitions(ad)
        .provisioned_throughput(pt)
        .send()
        .await;

    match create_table_response {
        Ok(out) => Ok(out),
        Err(e) => Err(Report::msg(format!("Could not create table: {}", e))),
    }
}
