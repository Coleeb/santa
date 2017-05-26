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

#ifndef SANTA__SANTA_DRIVER__SantaMACFPolicy_h
#define SANTA__SANTA_DRIVER__SantaMACFPolicy_h

#include <sys/proc.h>

extern "C" {
  #include <security/mac_policy.h>
}

class SantaMACFPolicy {

public:
  SantaMACFPolicy(mpo_cred_label_associate_fork_t *);
  ~SantaMACFPolicy();

  /// Starts the MACF listeners.
  int StartListener();

  /// Stops the MACF listeners.
  int StopListener();

//  SantaDecisionManager *decisionManager;

private:
  mac_policy_handle_t santa_mac_policy_handle_ = {0};
  mac_policy_ops santa_mac_policy_ops_ = {0};
  mac_policy_conf santa_mac_policy_conf_ = {0};
};

#endif /* SANTA__SANTA_DRIVER__SantaMACFPolicy_hpp */