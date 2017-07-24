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

#import "SNTProtoLog.h"

#import "EventLog.pbobjc.h"

#include <libproc.h>

#import "SNTCachedDecision.h"
#import "SNTFileInfo.h"

@implementation SNTProtoLog

- (instancetype)initWithLogPath:(NSString *)logPath {
  return [super initWithLogPath:logPath ?: @"/var/db/santa/events.pblog"];
}

- (void)logFileModification:(santa_message_t)message {
  SNTEventLogMessage *e = [[SNTEventLogMessage alloc] init];
  e.timestamp = [[NSDate date] timeIntervalSince1970];
  e.path = @(message.path);

  switch (message.action) {
    case ACTION_NOTIFY_DELETE: {
      e.action = SNTEventLogMessage_Action_Delete;
      break;
    }
    case ACTION_NOTIFY_EXCHANGE: {
      e.action = SNTEventLogMessage_Action_Exchange;
      e.fileopDetails.newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_LINK: {
      e.action = SNTEventLogMessage_Action_Link;
      e.fileopDetails.newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_RENAME: {
      e.action = SNTEventLogMessage_Action_Rename;
      e.fileopDetails.newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_WRITE: {
      e.action = SNTEventLogMessage_Action_Write;
      SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithPath:e.path];
      if (fileInfo.fileSize < 1024 * 1024) {
        e.sha256 = fileInfo.SHA256;
      } else {
        e.sha256 = @"TOO LARGE";
      }
      break;
    }
    default:
      return;
  }

  e.pid = message.pid;
  e.ppid = message.ppid;
  e.uid = message.uid;
  e.gid = message.gid;

  e.username = [self nameForUID:message.uid];
  e.groupname = [self nameForGID:message.gid];

  char ppath[PATH_MAX] = "(null)";
  proc_pidpath(message.pid, ppath, PATH_MAX);
  e.fileopDetails.processname = @(message.pname);
  e.fileopDetails.processpath = @(ppath);

  [self writeData:e.delimitedData];
}

- (void)logDeniedExecution:(SNTCachedDecision *)cd withMessage:(santa_message_t)message {
  [self logExecution:message withDecision:cd];
}

- (void)logAllowedExecution:(santa_message_t)message {
  __block SNTCachedDecision *cd;
  dispatch_sync(self.detailStoreQueue, ^{
    cd = self.detailStore[@(message.vnode_id)];
  });
  [self logExecution:message withDecision:cd];
}

- (void)logExecution:(santa_message_t)message withDecision:(SNTCachedDecision *)cd {
  SNTEventLogMessage *e = [[SNTEventLogMessage alloc] init];
  e.timestamp = [[NSDate date] timeIntervalSince1970];
  e.action = SNTEventLogMessage_Action_Execute;

  switch (cd.decision) {
    case SNTEventStateBlockBinary:
    case SNTEventStateBlockCertificate:
    case SNTEventStateBlockScope:
    case SNTEventStateBlockUnknown:
      e.execDetails.denied = YES;
      break;
    case SNTEventStateAllowBinary:
    case SNTEventStateAllowCertificate:
    case SNTEventStateAllowScope:
    case SNTEventStateAllowUnknown:
    default: {
      e.execDetails.denied = NO;
      NSMutableArray *array = [NSMutableArray array];
      [self addArgsForPid:message.pid toString:nil toArray:array];
      e.execDetails.argsArray = array;
      break;
    }
  }

  switch (cd.decision) {
    case SNTEventStateAllowBinary:
    case SNTEventStateBlockBinary:
      e.execDetails.reason = SNTEventLogMessage_EventLogMessageExec_Reason_Binary;
      break;
    case SNTEventStateAllowCertificate:
    case SNTEventStateBlockCertificate:
      e.execDetails.reason = SNTEventLogMessage_EventLogMessageExec_Reason_Certificate;
      break;
    case SNTEventStateAllowScope:
    case SNTEventStateBlockScope:
      e.execDetails.reason = SNTEventLogMessage_EventLogMessageExec_Reason_Scope;
      break;
    case SNTEventStateAllowUnknown:
    case SNTEventStateBlockUnknown:
      e.execDetails.reason = SNTEventLogMessage_EventLogMessageExec_Reason_Unknown;
      break;
    default:
      e.execDetails.reason = SNTEventLogMessage_EventLogMessageExec_Reason_Notrunning;
      break;
  }

  e.execDetails.details = cd.decisionExtra;

  e.sha256 = cd.sha256;
  e.path = @(message.path);

  SNTEventLogMessage_EventLogMessageExec_Cert *cert =
  [[SNTEventLogMessage_EventLogMessageExec_Cert alloc] init];
  cert.sha256 = cd.certSHA256;
  cert.commonName = cd.certCommonName;
  [e.execDetails.certsArray addObject:cert];

  e.pid = message.pid;
  e.ppid = message.ppid;
  e.uid = message.uid;
  e.gid = message.gid;

  e.username = [self nameForUID:message.uid];
  e.groupname = [self nameForGID:message.gid];

  [self writeData:e.delimitedData];
}

- (void)logDiskAppeared:(NSDictionary *)diskProperties {
  SNTEventLogMessage *e = [[SNTEventLogMessage alloc] init];

  e.timestamp = [[NSDate date] timeIntervalSince1970];
  e.action = SNTEventLogMessage_Action_Diskappear;

  NSString *dmgPath = @"";
  NSString *serial = @"";
  if ([diskProperties[@"DADeviceModel"] isEqual:@"Disk Image"]) {
    dmgPath = [self diskImageForDevice:diskProperties[@"DADevicePath"]];
  } else {
    serial = [self serialForDevice:diskProperties[@"DADevicePath"]];
    serial = [serial stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
  }

  NSString *model = [NSString stringWithFormat:@"%@ %@",
                     diskProperties[@"DADeviceVendor"] ?: @"",
                     diskProperties[@"DADeviceModel"] ?: @""];
  model = [model stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  double at = [diskProperties[@"DAAppearanceTime"] doubleValue];
  NSString *appearanceDateString =
      [self.dateFormatter stringFromDate:[NSDate dateWithTimeIntervalSinceReferenceDate:at]];

  e.path = [diskProperties[@"DAVolumePath"] path];
  e.diskDetails.volume = diskProperties[@"DAVolumeName"];
  e.diskDetails.bsdname = diskProperties[@"DAMediaBSDName"];
  e.diskDetails.fs = diskProperties[@"DAVolumeKind"];
  e.diskDetails.model = model;
  e.diskDetails.serial = serial;
  e.diskDetails.bus = diskProperties[@"DADeviceProtocol"];
  e.diskDetails.dmgpath = dmgPath;
  e.diskDetails.appearance = appearanceDateString;

  [self writeData:e.delimitedData];
}

- (void)logDiskDisappeared:(NSDictionary *)diskProperties {
  SNTEventLogMessage *e = [[SNTEventLogMessage alloc] init];

  e.timestamp = [[NSDate date] timeIntervalSince1970];
  e.action = SNTEventLogMessage_Action_Diskdisappear;
  e.path = [diskProperties[@"DAVolumePath"] path];
  e.diskDetails.volume = diskProperties[@"DAVolumeName"];
  e.diskDetails.bsdname = diskProperties[@"DAMediaBSDName"];

  [self writeData:e.delimitedData];
}

@end
