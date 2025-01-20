use serde::{Deserialize, Serialize};

use crate::shared::dbt;
use super::dbt::VirtualTableID;


#[derive(Serialize, Deserialize)]
pub struct TablesRequestData;
#[derive(Serialize, Deserialize)]
pub struct TablesResponseData {
    pub tables: Vec<dbt::VirtualTable>
}


#[derive(Serialize, Deserialize)]
pub struct TablesSpecificRequestData;
#[derive(Serialize, Deserialize)]
pub struct TablesSpecificResponseData {
    pub table: dbt::VirtualTable
}


#[derive(Serialize, Deserialize)]
pub struct TablesInsertRequestData {
    pub table: dbt::VirtualTable
}
#[derive(Serialize, Deserialize)]
pub struct TablesInsertResponseData {}


#[derive(Serialize, Deserialize)]
pub struct TablesDeleteRequestData {}
#[derive(Serialize, Deserialize)]
pub struct TablesDeleteResponseData {}


#[derive(Serialize, Deserialize)]
pub struct OffersRequestData;
#[derive(Serialize, Deserialize)]
pub struct OffersResponseData {
    pub offers: Vec<dbt::Offer>
}


#[derive(Serialize, Deserialize)]
pub struct OffersSpecificRequestData;
#[derive(Serialize, Deserialize)]
pub struct OffersSpecificResponseData {
    pub offer: dbt::Offer
}


#[derive(Serialize, Deserialize)]
pub struct OffersInsertRequestData {
    pub offer: dbt::Offer
}
#[derive(Serialize, Deserialize)]
pub struct OffersInsertResponseData {}



pub enum RequestKind {

    Tables,
    TablesSpecific,
    Offers,
    OffersSpecific

}

pub struct Request {

    kind: RequestKind,
    payload: serde_json::Value

}

pub enum Authority {
    User,
    Admin
}

pub trait Communication {

    fn authority(&self) -> Authority;
    fn send_request(&mut self);

}

// impl Communication for Request {

//     fn authority(&self) -> Authority {
//         match self.kind {
//             RequestKind::Tables => Authority::Admin,
//             RequestKind::TablesSpecific => Authority::Admin
//         }
//     }

// }