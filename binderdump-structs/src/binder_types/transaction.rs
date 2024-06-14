pub use binderdump_sys::binder_transaction_data;
use plain::Plain;

unsafe impl Plain for Transaction {}
unsafe impl Plain for TransactionSg {}

// SG = Scatter Gather
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TransactionSg {
    transaction_data: binder_transaction_data,
    buffers_size: u64,
}

impl Default for TransactionSg {
    fn default() -> Self {
        let transaction_data = unsafe { std::mem::zeroed::<binder_transaction_data>() };
        Self {
            transaction_data,
            buffers_size: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Transaction {
    transaction_data: binder_transaction_data,
}

impl Default for Transaction {
    fn default() -> Self {
        let transaction_data = unsafe { std::mem::zeroed::<binder_transaction_data>() };
        Self { transaction_data }
    }
}
