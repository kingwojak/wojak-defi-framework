mod adex_proc_impl;
mod command;
mod response_handler;

pub(super) use adex_proc_impl::AdexProc;
pub(super) use response_handler::{ResponseHandler, ResponseHandlerImpl, SmartFractPrecision};

pub(super) struct OrderbookSettings {
    pub(super) uuids: bool,
    pub(super) min_volume: bool,
    pub(super) max_volume: bool,
    pub(super) publics: bool,
    pub(super) address: bool,
    pub(super) age: bool,
    pub(super) conf_settings: bool,
    pub(super) asks_limit: Option<usize>,
    pub(super) bids_limit: Option<usize>,
}

pub(super) struct OrdersHistorySettings {
    pub(super) takers_detailed: bool,
    pub(super) makers_detailed: bool,
    pub(super) warnings: bool,
    pub(super) common: bool,
}
