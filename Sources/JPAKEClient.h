// JPAKEClient.h

#import <Foundation/Foundation.h>

#import "JPAKEParty.h"
#import "ASIHTTPRequest.h"

@class JPAKEClient;

@protocol JPAKEClientDelegate
- (void) client: (JPAKEClient*) client didChangeToState: (int) state;
- (void) client: (JPAKEClient*) client didGenerateSecret: (NSString*) secret;
- (void) client: (JPAKEClient*) client didFailWithError: (NSError*) error;
- (void) client: (JPAKEClient*) client didExchangeKey: (NSData*) key;
- (void) client: (JPAKEClient*) client didReceivePayload: (id) payload;
@end

@interface JPAKEClient : NSObject {
  @private
	NSURL* _server;
	id<JPAKEClientDelegate> _delegate;
  @private
	ASIHTTPRequest* _request;
	NSTimer* _timer;
	NSString* _channel;
	NSString* _password;
	JPAKEParty* _party;
	NSString* _etag;
	NSData* _key;
}

- (id) initWithServer: (NSURL*) server delegate: (id<JPAKEClientDelegate>) delegate;

- (void) start;
- (void) cancel;

@end
