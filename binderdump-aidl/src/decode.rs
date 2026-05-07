// Per-parameter byte decoding hook. Not implemented yet:
// the dissector still shows the raw transaction payload bytes.
// When implemented, this module will decode the parcel buffer
// using `Method::params` to surface each argument as its own field.
//
// TODO - implement ParamDecoder trait and walk the parcel layout
// described in libbinder Parcel.cpp / hidl Parcel.cpp.
