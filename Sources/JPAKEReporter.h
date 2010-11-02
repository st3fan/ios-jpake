// JPAKEReporter.h

#import <Foundation/Foundation.h>
#import "ASINetworkQueue.h"

@interface JPAKEReporter : NSObject {
  @private
	NSURL* _server;
	ASINetworkQueue* _queue;
}

- (id) initWithServer: (NSURL*) server;
- (void) reportCode: (NSInteger) code message: (NSString*) message;

@end
