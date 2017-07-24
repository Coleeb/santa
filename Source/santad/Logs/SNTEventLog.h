/// Copyright 2015 Google Inc. All rights reserved.
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

@import Foundation;

#import "SNTKernelCommon.h"

@class SNTCachedDecision;

///
///  A protocol for logging events.
///
@protocol SNTEventLogger
@required
- (void)logDiskAppeared:(NSDictionary *)diskProperties;
- (void)logDiskDisappeared:(NSDictionary *)diskProperties;
- (void)logFileModification:(santa_message_t)message;
- (void)logDeniedExecution:(SNTCachedDecision *)cd withMessage:(santa_message_t)message;
- (void)logAllowedExecution:(santa_message_t)message;

@optional
///
///  If subclassing SNTEventLog this method is already implemented. Override if you implement your
///  own detailStore.
///
- (void)saveDecisionDetails:(SNTCachedDecision *)cd;
@end

///
///  A class that provides helper properties and methods for classes that want to implement the
///  SNTEventLogger protocol.
///
@interface SNTEventLog : NSObject
// A cache for whitelisted executions. Only access on the detailStoreQueue.
@property(readonly, nonatomic) NSMutableDictionary<NSNumber *, SNTCachedDecision *> *detailStore;

// A queue for accessing the detailStore
@property(readonly, nonatomic) dispatch_queue_t detailStoreQueue;

// A cache for usernames and groups. Thread safe.
@property(readonly, nonatomic) NSCache<NSNumber *, NSString *> *userNameMap;
@property(readonly, nonatomic) NSCache<NSNumber *, NSString *> *groupNameMap;

// A UTC Date formatter. Use this to generate all date strings.
@property(readonly, nonatomic) NSDateFormatter *dateFormatter;

///
///  String formatter helpers
///
- (void)addArgsForPid:(pid_t)pid toString:(NSMutableString *)str toArray:(NSMutableArray *)array;
- (NSString *)diskImageForDevice:(NSString *)devPath;
- (NSString *)nameForUID:(uid_t)uid;
- (NSString *)nameForGID:(gid_t)gid;
- (NSString *)sanitizeCString:(const char *)str ofLength:(NSUInteger)length;
- (NSString *)sanitizeString:(NSString *)inStr;
- (NSString *)serialForDevice:(NSString *)devPath;

///
///  Writes data to a log file. Only to be used on objects created with initWithLogPath:.
///
- (void)writeData:(NSData *)data;

///
///  Creates a new object with file logging capabilities. Wraps init.
///  Log rotation at 25MB.
///  Archived log pruning at 100MB.
///  HUP signal archives current log.
///
- (instancetype)initWithLogPath:(NSString *)logPath;

///
///  Creates a new object that initializes the exported properties for use.
///
- (instancetype)init;

@end
