use std::collections::HashMap;

use anyhow::{Error, Result};
use aws_sdk_dynamodb::{
    operation::create_table::CreateTableOutput,
    types::{
        AttributeDefinition, AttributeValue, KeySchemaElement, KeyType, ProvisionedThroughput,
        ScalarAttributeType,
    },
    Client,
};
use serde::{Deserialize, Serialize};
use serde_dynamo::aws_sdk_dynamodb_0_33::{from_items, to_item};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::model::Model;

pub static LOCAL_DB: OnceCell<Client> = OnceCell::const_new();

pub async fn get_or_init() -> &'static Client {
    LOCAL_DB
        .get_or_init(|| async {
            let config = aws_config::from_env().profile_name("local").load().await;
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

    let mut reqs: HashMap<String, Vec<String>> = HashMap::new();
    // todo did this to also build indices
    reqs.insert(
        "users".to_owned(),
        vec![
            "id".to_owned(),
            "rsi_id".to_owned(),
            "email".to_owned(),
            "discord_sf".to_owned(),
        ],
    );
    reqs.insert(
        "applications".to_owned(),
        vec![
            "id".to_owned(),
            "rsi_id".to_owned(),
            "email".to_owned(),
            "discord_sf".to_owned(),
        ],
    );

    // make whatever is missing
    let l = reqs
        .keys()
        .filter(|&x| !names.contains(x))
        .cloned()
        .collect::<Vec<String>>();
    println!("Missing: {:?}", &l);

    for n in l {
        match create_table(client, &n, "id").await {
            Ok(o) => {
                println!("Response:\n {:?}", o);
                // todo create indices
                // for i in reqs.get(&n) {
                //     create_index(client, &n, &i).await;
                // }
            }
            Err(e) => {
                println!("Error:\n {}", e);
            }
        }
    }

    Ok(())
}

pub async fn get_item_from_table_with_filter_by_index<T>(
    column_name: &str,
    value: &str,
) -> Result<Option<T>>
where
    T: Model + Serialize + for<'a> Deserialize<'a> + Clone,
{
    let client = get_or_init().await;
    let req = client
        .query()
        .index_name(format!("{}-index", column_name))
        .table_name(T::TABLE)
        .key_condition_expression(format!("#{} = :{}", column_name, column_name))
        .expression_attribute_names(format!("#{}", column_name), column_name)
        .expression_attribute_values(
            format!(":{}", column_name),
            AttributeValue::S(value.to_owned()),
        );
    let result = req.send().await?;

    if let Some(items) = result.items {
        let t: Vec<T> = from_items(items)?;
        if let Some(ret) = t.first() {
            return Ok(Some(ret.clone()));
        }
    }
    Ok(None)
}

pub async fn get_all_from_table_with_filter_by_index<T>(
    column_name: &str,
    value: &str,
) -> Result<Vec<T>>
where
    T: Model + Serialize + for<'a> Deserialize<'a> + Clone,
{
    let client = get_or_init().await;
    let req = client
        .query()
        .index_name(format!("{}-index", column_name))
        .table_name(T::TABLE)
        .key_condition_expression(format!("#{} = :{}", column_name, column_name))
        .expression_attribute_names(format!("#{}", column_name), column_name)
        .expression_attribute_values(
            format!(":{}", column_name),
            AttributeValue::S(value.to_owned()),
        );
    let result = req.send().await?;

    match result.items {
        Some(items) => {
            let t: Vec<T> = from_items(items)?;
            Ok(t)
        }
        None => Ok(Vec::new()),
    }
}

pub async fn get_item_from_table_with_filter_by_id<T>(value: &str) -> Result<Option<T>>
where
    T: Model + Serialize + for<'a> Deserialize<'a> + Clone,
{
    let client = get_or_init().await;
    let req = client
        .query()
        .table_name(T::TABLE)
        .key_condition_expression("#id = :id")
        .expression_attribute_names("#id", "id")
        .expression_attribute_values(":id", AttributeValue::S(value.to_owned()));
    let result = req.send().await?;

    if let Some(items) = result.items {
        let t: Vec<T> = from_items(items)?;
        let ret: T = t
            .first()
            .ok_or(Error::msg(format!(
                "Item [{}]<{}> was not found.",
                std::any::type_name::<T>(),
                value
            )))?
            .clone();
        Ok(Some(ret.clone()))
    } else {
        Ok(None)
    }
}

pub async fn put_item<T>(item: T) -> Result<T>
where
    T: Model + Serialize + for<'a> Deserialize<'a> + Clone,
{
    let client = get_or_init().await;

    let i = to_item(item.clone())?;

    let request = client.put_item().table_name(T::TABLE).set_item(Some(i));
    let _resp = request.send().await?;

    Ok(item)
}

pub async fn delete_item<T>(id: Uuid) -> Result<()>
where
    T: Model + Serialize + for<'a> Deserialize<'a> + Clone,
{
    let client = get_or_init().await;

    let request = client
        .delete_item()
        .table_name(T::TABLE)
        .key(id, AttributeValue::S(id.into()));
    let _resp = request.send().await?;

    Ok(())
}

pub async fn update_item<T>(id: String, item: T) -> Result<T>
where
    T: Model + Serialize + for<'a> Deserialize<'a> + Clone,
{
    if let Ok(Some(_)) = get_item_from_table_with_filter_by_id::<T>(&id.to_string()).await {
        let client = get_or_init().await;

        let i = to_item(item.clone())?;

        let request = client.put_item().table_name(T::TABLE).set_item(Some(i));
        let _resp = request.send().await?;

        Ok(item)
    } else {
        Err(Error::msg(format!(
            "Item [{}]<{}> was not found.",
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
        Err(e) => Err(Error::msg(format!("Could not create table: {}", e))),
    }
}
