/// Copyright 2017 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#include "SantaMACFPolicy.h"

#include "SNTLogging.h"

SantaMACFPolicy::SantaMACFPolicy(mpo_cred_label_associate_fork_t *fork_handler) {
  LOGD("SantaMACFPolicy::SantaMACFPolicy");

  santa_mac_policy_ops_ = {
    .mpo_cred_label_associate_fork = fork_handler,
  };

  santa_mac_policy_conf_ = {
    .mpc_name            = "Santa",
    .mpc_fullname        = "Santa Binary Whitelisting",
    .mpc_labelnames      = NULL,
    .mpc_labelname_count = 0,
    .mpc_ops             = &santa_mac_policy_ops_,
    .mpc_loadtime_flags  = MPC_LOADTIME_FLAG_UNLOADOK,
    .mpc_field_off       = NULL,
    .mpc_runtime_flags   = 0,
    .mpc_list            = NULL,
    .mpc_data            = NULL
  };
}

SantaMACFPolicy::~SantaMACFPolicy() {
  LOGD("SantaMACFPolicy::~SantaMACFPolicy");
}

int SantaMACFPolicy::StartListener() {
  LOGD("SantaMACFPolicy::StartListener");

  int ret = mac_policy_register(&santa_mac_policy_conf_, &santa_mac_policy_handle_, NULL);
  LOGD("mac_policy_register %i", ret);
  return ret;
}

int SantaMACFPolicy::StopListener() {
  LOGD("SantaMACFPolicy::StopListener");
  int ret = mac_policy_unregister(santa_mac_policy_handle_);
  LOGD("mac_policy_unregister %i", ret);
  return ret;
}
