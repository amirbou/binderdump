#include "wireshark_shims.h"
#include <epan/proto.h>

void binderdump_proto_item_set_generated(proto_item *pi) { proto_item_set_generated(pi); }
