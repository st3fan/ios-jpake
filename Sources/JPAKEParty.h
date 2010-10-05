// JPAKEParty.h

#import <Foundation/Foundation.h>
#include <openssl/jpake.h>

@interface JPAKEParty : NSObject {
  @private
	NSString* _signerIdentity;
	JPAKE_CTX* _ctx;
}

+ (id) partyWithPassword: (NSString*) password modulusLength: (NSUInteger) modulesLength signerIdentity: (NSString*) signerIdentity peerIdentity: (NSString*) peerIdentity;
- (id) initWithPassword: (NSString*) password modulusLength: (NSUInteger) modulesLength signerIdentity: (NSString*) signerIdentity peerIdentity: (NSString*) peerIdentity;

- (NSDictionary*) generateMessageOne;
- (NSDictionary*) generateMessageTwoFromMessageOne: (NSDictionary*) one;
- (NSData*) generateKeyFromMessageTwo: (NSDictionary*) two;

@end
