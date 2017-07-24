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

#import "SNTFileLog.h"

#include <libproc.h>

#import "SNTCachedDecision.h"
#import "SNTConfigurator.h"

static NSString *const kLogPrefix = @"[%@] I santad: ";

@implementation SNTFileLog

- (instancetype)initWithLogPath:(NSString *)logPath {
  return [super initWithLogPath:logPath ?: @"/var/db/santa/santa.log"];
}

- (void)logFileModification:(santa_message_t)message {
  NSString *action, *newpath;
  NSString *path = @(message.path);

  switch (message.action) {
    case ACTION_NOTIFY_DELETE: {
      action = @"DELETE";
      break;
    }
    case ACTION_NOTIFY_EXCHANGE: {
      action = @"EXCHANGE";
      newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_LINK: {
      action = @"LINK";
      newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_RENAME: {
      action = @"RENAME";
      newpath = @(message.newpath);
      break;
    }
    case ACTION_NOTIFY_WRITE: {
      action = @"WRITE";
      break;
    }
    default: action = @"UNKNOWN"; break;
  }

  // init the string with 2k capacity to avoid reallocs
  NSMutableString *outStr = [NSMutableString stringWithCapacity:2048];
  [outStr appendFormat:kLogPrefix, [self.dateFormatter stringFromDate:[NSDate date]]];
  [outStr appendFormat:@"action=%@|path=%@", action, [self sanitizeString:path]];
  if (newpath) {
    [outStr appendFormat:@"|newpath=%@", [self sanitizeString:newpath]];
  }
  char ppath[PATH_MAX] = "(null)";
  proc_pidpath(message.pid, ppath, PATH_MAX);

  [outStr appendFormat:@"|pid=%d|ppid=%d|process=%s|processpath=%s|uid=%d|user=%@|gid=%d|group=%@\n",
   message.pid, message.ppid, message.pname, ppath,
   message.uid, [self nameForUID:message.uid],
   message.gid, [self nameForGID:message.gid]];

  [self writeData:[outStr dataUsingEncoding:NSUTF8StringEncoding]];
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
  NSString *d, *r;
  BOOL logArgs = NO;

  switch (cd.decision) {
    case SNTEventStateAllowBinary:
      d = @"ALLOW";
      r = @"BINARY";
      logArgs = YES;
      break;
    case SNTEventStateAllowCertificate:
      d = @"ALLOW";
      r = @"CERT";
      logArgs = YES;
      break;
    case SNTEventStateAllowScope:
      d = @"ALLOW";
      r = @"SCOPE";
      logArgs = YES;
      break;
    case SNTEventStateAllowUnknown:
      d = @"ALLOW";
      r = @"UNKNOWN";
      logArgs = YES;
      break;
    case SNTEventStateBlockBinary:
      d = @"DENY";
      r = @"BINARY";
      break;
    case SNTEventStateBlockCertificate:
      d = @"DENY";
      r = @"CERT";
      break;
    case SNTEventStateBlockScope:
      d = @"DENY";
      r = @"SCOPE";
      break;
    case SNTEventStateBlockUnknown:
      d = @"DENY";
      r = @"UNKNOWN";
      break;
    default:
      d = @"ALLOW";
      r = @"NOTRUNNING";
      logArgs = YES;
      break;
  }

  // init the string with 4k capacity to avoid reallocs
  NSMutableString *outLog = [[NSMutableString alloc] initWithCapacity:4096];
  [outLog appendFormat:kLogPrefix, [self.dateFormatter stringFromDate:[NSDate date]]];
  [outLog appendFormat:@"action=EXEC|decision=%@|reason=%@", d, r];

  if (cd.decisionExtra) {
    [outLog appendFormat:@"|explain=%@", cd.decisionExtra];
  }

  [outLog appendFormat:@"|sha256=%@|path=%@", cd.sha256, [self sanitizeString:@(message.path)]];

  if (logArgs) {
    [outLog appendString:@"|args="];
    [self addArgsForPid:message.pid toString:outLog toArray:nil];
  }

  if (cd.certSHA256) {
    [outLog appendFormat:@"|cert_sha256=%@|cert_cn=%@", cd.certSHA256,
     [self sanitizeString:cd.certCommonName]];
  }

  if (cd.quarantineURL) {
    [outLog appendFormat:@"|quarantine_url=%@", [self sanitizeString:cd.quarantineURL]];
  }

  NSString *mode;
  switch ([[SNTConfigurator configurator] clientMode]) {
    case SNTClientModeMonitor:
      mode = @"M"; break;
    case SNTClientModeLockdown:
      mode = @"L"; break;
    default:
      mode = @"U"; break;
  }

  [outLog appendFormat:@"|pid=%d|ppid=%d|uid=%d|user=%@|gid=%d|group=%@|mode=%@\n",
   message.pid, message.ppid,
   message.uid, [self nameForUID:message.uid],
   message.gid, [self nameForGID:message.gid],
   mode];

  [self writeData:[outLog dataUsingEncoding:NSUTF8StringEncoding]];
}


- (void)logDiskAppeared:(NSDictionary *)diskProperties {
  if (![diskProperties[@"DAVolumeMountable"] boolValue]) return;

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

  NSString *outLog =
      [NSString stringWithFormat:
          @"%@action=DISKAPPEAR|mount=%@|volume=%@|bsdname=%@|"
          @"fs=%@|model=%@|serial=%@|bus=%@|dmgpath=%@|appearance=%@\n",
          [NSString stringWithFormat:kLogPrefix, [self.dateFormatter stringFromDate:[NSDate date]]],
          [diskProperties[@"DAVolumePath"] path] ?: @"",
          diskProperties[@"DAVolumeName"] ?: @"",
          diskProperties[@"DAMediaBSDName"] ?: @"",
          diskProperties[@"DAVolumeKind"] ?: @"",
          model ?: @"",
          serial,
          diskProperties[@"DADeviceProtocol"] ?: @"",
          dmgPath,
          appearanceDateString];

  [self writeData:[outLog dataUsingEncoding:NSUTF8StringEncoding]];
}


- (void)logDiskDisappeared:(NSDictionary *)diskProperties {
  if (![diskProperties[@"DAVolumeMountable"] boolValue]) return;

  NSString *outLog =
      [NSString stringWithFormat:@"%@action=DISKDISAPPEAR|mount=%@|volume=%@|bsdname=%@\n",
          [NSString stringWithFormat:kLogPrefix, [self.dateFormatter stringFromDate:[NSDate date]]],
          [diskProperties[@"DAVolumePath"] path] ?: @"",
          diskProperties[@"DAVolumeName"] ?: @"",
          diskProperties[@"DAMediaBSDName"]];
  [self writeData:[outLog dataUsingEncoding:NSUTF8StringEncoding]];
}

@end
