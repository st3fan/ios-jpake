/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Firefox Home.
 *
 * The Initial Developer of the Original Code is the Mozilla Foundation.
 *
 * Portions created by the Initial Developer are Copyright (C) 2010
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 *  Stefan Arentz <stefan@arentz.ca>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#import "NSData+AES.h"
#import "NSData+Encoding.h"
#import "NSData+SHA.h"

#import "JPAKEClient.h"
#import "JSON.h"

@implementation NSString (JPAKE)

/**
 * Generate a JPAKE Secret. Currently implemented as 4 random characters.
 */

+ (NSString*) stringWithJPAKESecret
{
	static char* permittedCharacters = "abcdefghijkmnpqrstuvwxyz23456789";

	NSMutableString* secret = [NSMutableString stringWithCapacity: 8];
		
	srandomdev();

	int n = strlen(permittedCharacters);
	
	for (int i = 0; i < 8; i++) {
		[secret appendFormat: @"%c", permittedCharacters[random() % n]];
	}
	
	return secret;
}

/**
 * Generate a session id, which currently is 256 random characters. Using hex here.
 */

+ (NSString*) stringWithJPAKEClientIdentifier
{
	NSMutableString* identifier = [NSMutableString stringWithCapacity: 16];
	
	srandomdev();
	
	for (int i = 0; i < 256; i++) {
		[identifier appendFormat: @"%x", (random() % 16)];
	}
	
	return identifier;
}

@end

@implementation JPAKEClient

@synthesize pollRetries = _pollRetries;
@synthesize pollInterval = _pollInterval;
@synthesize pollDelay = _pollDelay;

- (id) initWithServer: (NSURL*) server delegate: (id<JPAKEClientDelegate>) delegate reporter: (JPAKEReporter*) reporter
{
	if ((self = [super init]) != nil) {
		_server = [server retain];
		_delegate = delegate;
		_reporter = [reporter retain];
		_clientIdentifier = [[NSString stringWithJPAKEClientIdentifier] retain];
		_pollRetries = 300;
		_pollDelay = 2000;
		_pollInterval = 1000;
		_queue = [ASINetworkQueue new];
		[_queue go];
	}
	
	return self;
}

- (void) dealloc
{
	[_reporter release];
	
	[_queue reset];
	[_queue release];

	if (_timer != nil) {
		[_timer invalidate];
		[_timer release];
		_timer = nil;
	}

	[_channel release];
	[_secret release];
	[_clientIdentifier release];
	[_party release];
	[_etag release];
	[_key release];
	[_server release];

	[super dealloc];
}

#pragma mark -

- (NSDictionary*) messageWithType: (NSString*) type payload: (id) payload
{
	return [NSDictionary dictionaryWithObjectsAndKeys: type, @"type", payload, @"payload", nil];
}

- (NSError*) errorWithCode: (NSInteger) code localizedDescriptionKey: (NSString*) localizedDescriptionKey
{
	NSDictionary* userInfo = [NSDictionary dictionaryWithObject: localizedDescriptionKey forKey: @"NSLocalizedDescriptionKey"];
	return [NSError errorWithDomain: @"JPAKEClient" code: code userInfo: userInfo];
}



- (NSError*) unexpectedServerResponseError
{
	return [self errorWithCode: kJPAKEClientErrorUnexpectedServerResponse
		localizedDescriptionKey: @"The server returned an unexpected response"];
}

- (NSError*) invalidServerResponseError
{
	return [self errorWithCode: kJPAKEClientErrorInvalidServerResponse
		localizedDescriptionKey: @"The server returned an invalid response"];
}

- (NSError*) timeoutError
{
	return [self errorWithCode: kJPAKEClientErrorPeerTimeout
		localizedDescriptionKey: @"Timeout while waiting for the peer response"];
}

#pragma mark -

- (BOOL) validateBasicMessage :(NSDictionary*) message ofType: (NSString*) expectedType
{
	if (message == nil) {
		return NO;
	}
	
	if ([message isKindOfClass: [NSDictionary class]] == NO) {
		return NO;
	}
	
	NSString* type = [message objectForKey: @"type"];
	if (type == nil || [type isEqualToString: expectedType] == NO) {
		return NO;
	}
	
	if ([message objectForKey: @"payload"] == nil) {
		return NO;
	}
	
	return YES;
}

- (BOOL) validateDesktopMessageOne: (NSDictionary*) message
{
	if ([self validateBasicMessage: message ofType: @"sender1"] == NO) {
		return NO;
	}
	
	// Check for the existence of a payload dictionary
	
	NSDictionary* payload = [message objectForKey: @"payload"];
	if (payload == nil || [payload isKindOfClass: [NSDictionary class]] == NO) {
		return NO;
	}
	
	// Check if the payload has the two zkp dictionaries
	
	NSDictionary* zkp_x1 = [payload objectForKey: @"zkp_x1"];
	if (zkp_x1 == nil || [zkp_x1 isKindOfClass: [NSDictionary class]] == NO) {
		return NO;
	}

	NSDictionary* zkp_x2 = [payload objectForKey: @"zkp_x1"];
	if (zkp_x2 == nil || [zkp_x2 isKindOfClass: [NSDictionary class]] == NO) {
		return NO;
	}
	
	// Check for the presence of the numbers .. we just check if they are strings

	if ([[payload objectForKey: @"gx1"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}

	if ([[payload objectForKey: @"gx2"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}

	if ([[zkp_x1 objectForKey: @"gr"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}

	if ([[zkp_x1 objectForKey: @"b"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}

	if ([[zkp_x2 objectForKey: @"gr"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}

	if ([[zkp_x2 objectForKey: @"b"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}
	
	return YES;
}

- (BOOL) validateDesktopMessageTwo: (NSDictionary*) message
{
	if ([self validateBasicMessage: message ofType: @"sender2"] == NO) {
		return NO;
	}

	// Check for the existence of a payload dictionary
	
	NSDictionary* payload = [message objectForKey: @"payload"];
	if (payload == nil || [payload isKindOfClass: [NSDictionary class]] == NO) {
		return NO;
	}
	
	// Check if the payload has the zkp dictionary
	
	NSDictionary* zkp_A = [payload objectForKey: @"zkp_A"];	
	if (zkp_A == nil || [zkp_A isKindOfClass: [NSDictionary class]] == NO) {
		return NO;
	}
	
	// Check for the presence of the numbers .. we just check if they are strings

	if ([[payload objectForKey: @"A"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}

	if ([[zkp_A objectForKey: @"gr"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}

	if ([[zkp_A objectForKey: @"b"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}

	return YES;
}

- (BOOL) validateDesktopMessageThree: (NSDictionary*) message
{
	if ([self validateBasicMessage: message ofType: @"sender3"] == NO) {
		return NO;
	}
	
	// Check for the existence of a payload dictionary
	
	NSDictionary* payload = [message objectForKey: @"payload"];
	if (payload == nil || [payload isKindOfClass: [NSDictionary class]] == NO) {
		return NO;
	}

	// Check if the crypto fields are there
	
	if ([[payload objectForKey: @"ciphertext"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}	

	if ([[payload objectForKey: @"IV"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}	

	if ([[payload objectForKey: @"hmac"] isKindOfClass: [NSString class]] == NO) {
		return NO;
	}	

	return YES;
}

#pragma mark -

- (void) deleteChannelDidFinish: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#deleteChannelDidFinish");
}

- (void) deleteChannelDidFail: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#deleteChannelDidFail");
}

- (void) deleteChannel
{
	NSLog(@"JPAKEClient#deleteChannel");
	
	ASIHTTPRequest* request = [ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]];
	if (request != nil) {
		[request setShouldAttemptPersistentConnection: NO];
		[request setRequestMethod: @"DELETE"];
		[request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[request setDelegate: self];
		[request setDidFinishSelector: @selector(deleteChannelDidFinish:)];
		[request setDidFailSelector: @selector(deleteChannelDidFail:)];
		[_queue addOperation: request];
	}		
}

#pragma mark -

- (NSString*) decryptPayload: (NSDictionary*) payload withKey: (NSData*) key error: (NSError**) error
{
	// Generate the two different keys for HMAC-SHA256 and AES
	//
	// AES:  T(1) = HMAC-SHA256(key_string, "" + "Sync-AES_256_CBC-HMAC256" + 0x01)
	// HMAC: T(2) = HMAC-SHA256(key_string, T(1) + Sync-AES_256_CBC-HMAC256" + 0x02)
	
	const char* label1 = "Sync-AES_256_CBC-HMAC256\x01";
	NSMutableData* cryptoHashKey = [NSMutableData dataWithBytes: label1 length: strlen(label1)];
	NSData* cryptoKey = [key HMACSHA256WithKey: cryptoHashKey];
	
	const char* label2 = "Sync-AES_256_CBC-HMAC256\x02";
	NSMutableData* hmacHashKey = [NSMutableData dataWithData: cryptoKey];
	[hmacHashKey appendBytes: label2 length: strlen(label2)];
	NSData* hmacKey = [key HMACSHA256WithKey: hmacHashKey];

	//

	NSData* iv = [[[NSData alloc] initWithBase64EncodedString: [payload objectForKey: @"IV"]] autorelease];
	if (iv == nil || [iv length] != 16) {
		if (error != NULL) {
			*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		}
		return nil;
	}
	
	NSData* ciphertext = [[[NSData alloc] initWithBase64EncodedString: [payload objectForKey: @"ciphertext"]] autorelease];
	if (ciphertext == nil || [ciphertext length] == 0) {
		if (error != NULL) {
			*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		}
		return nil;
	}
	
	NSData* hmac = [[[NSData alloc] initWithBase16EncodedString: [payload objectForKey: @"hmac"]] autorelease];
	if (hmac == nil || [hmac length] != 32) {
		if (error != NULL) {
			*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		}
		return nil;
	}

	NSData* cipherTextData = [[payload objectForKey: @"ciphertext"] dataUsingEncoding: NSASCIIStringEncoding];

	NSData* hmacValue = [cipherTextData HMACSHA256WithKey: hmacKey];
	if (hmacValue == nil || [hmac isEqualToData: hmacValue] == NO) {
		if (error != NULL) {
			*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		}
		return nil;
	}
	
	NSData* plaintext = [NSData plaintextDataByAES256DecryptingCiphertextData: ciphertext key: cryptoKey iv: iv];
	if (plaintext == nil) {
		if (error != NULL) {
			*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		}
		return nil;
	}

	NSString* json = [[[NSString alloc] initWithData: plaintext encoding: NSUTF8StringEncoding] autorelease];
	if (json == nil) {
		if (error != NULL) {
			*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		}
		return nil;
	}
	
	return json;
}

- (void) getDesktopMessageThreeDidFinish: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#getDesktopMessageThreeDidFinish: %@", request);

	[_timer release];
	_timer = nil;

	switch ([request responseStatusCode]) {
		case 304: {
			if (_pollRetryCount < _pollRetries) {
				_timer = [[NSTimer scheduledTimerWithTimeInterval: ((NSTimeInterval) _pollInterval) / 1000.0 target: self
					selector: @selector(getDesktopMessageThree) userInfo: nil repeats: NO] retain];
			} else {
				[_delegate client: self didFailWithError: [self timeoutError]];
			}
			break;
		}
		
		case 200: {
			NSDictionary* message = [[request responseString] JSONValue];
			if ([self validateDesktopMessageThree: message] == NO) {
				[_delegate client: self didFailWithError: [self invalidServerResponseError]];
			} else {
				NSError* error = nil;
				NSString* json = [self decryptPayload: [message objectForKey: @"payload"] withKey: _key error: &error];
				if (error != nil) {
					[_delegate client: self didFailWithError: error];
				} else {
					[_delegate client: self didReceivePayload: [json JSONValue]];
				}
			}
			break;
		}
		
		default: {
			[_delegate client: self didFailWithError: [self unexpectedServerResponseError]];
		}
	}
}

- (void) getDesktopMessageThreeDidFail: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#getDesktopMessageThreeDidFail: %@", request);
	[_delegate client: self didFailWithError: [request error]];
}

- (void) getDesktopMessageThree
{
	NSLog(@"JPAKEClient#getDesktopMessageThree");
	
	ASIHTTPRequest* request = [ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]];
	if (request != nil) {
		[request setShouldAttemptPersistentConnection: NO];
		[request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[request addRequestHeader: @"If-None-Match" value: _etag];
		[request setDelegate: self];
		[request setDidFinishSelector: @selector(getDesktopMessageThreeDidFinish:)];
		[request setDidFailSelector: @selector(getDesktopMessageThreeDidFail:)];
		[_queue addOperation: request];
	}	
}

#pragma mark -

- (void) putMobileMessageThreeDidFinish: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#putMobileMessageThreeDidFinish: %@", request);

	if ([request responseStatusCode] != 200) {
		[_delegate client: self didFailWithError: [self unexpectedServerResponseError]];
		return;
	}

	// Remember the etag
	[_etag release];
	_etag = [[[request responseHeaders] objectForKey: @"Etag"] retain];

	// Poll for the desktop's message three
	_pollRetryCount = 0;
	_timer = [[NSTimer scheduledTimerWithTimeInterval: ((NSTimeInterval) _pollDelay) / 1000.0
		target: self selector: @selector(getDesktopMessageThree) userInfo: nil repeats: NO] retain];
}

- (void) putMobileMessageThreeDidFail: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#putMobileMessageThreeDidFail: %@", request);
	[_delegate client: self didFailWithError: [request error]];
}

- (void) putMobileMessageThree
{
	NSLog(@"JPAKEClient#putMobileMessageThree");

	NSString* payload = [[[_key SHA256Hash] SHA256Hash] base16Encoding];

	NSDictionary* message = [self messageWithType: @"receiver3" payload: payload];
	NSString* json = [message JSONRepresentation];
	NSLog(@"   Putting %@", json);
	NSMutableData* data = [NSMutableData dataWithData: [json dataUsingEncoding: NSUTF8StringEncoding]];

	ASIHTTPRequest* request = [ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]];
	if (request != nil) {
		[request setShouldAttemptPersistentConnection: NO];
		[request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[request setRequestMethod: @"PUT"];
		[request setPostBody: data];
		[request setDelegate: self];
		[request setDidFinishSelector: @selector(putMobileMessageThreeDidFinish:)];
		[request setDidFailSelector: @selector(putMobileMessageThreeDidFail:)];
		[_queue addOperation: request];
	}	
}

#pragma mark -

- (void) getDesktopMessageTwoDidFinish: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#getDesktopMessageTwoDidFinish: %@", request);
	
	[_timer release];
	_timer = nil;

	switch ([request responseStatusCode]) {
		case 304: {
			if (_pollRetryCount < _pollRetries) {
				_timer = [[NSTimer scheduledTimerWithTimeInterval: ((NSTimeInterval) _pollInterval) / 1000.0
					target: self selector: @selector(getDesktopMessageTwo) userInfo: nil repeats: NO] retain];
			} else {
				[_delegate client: self didFailWithError: [self timeoutError]];
			}
			break;
		}
		
		case 200: {
			NSDictionary* message = [[request responseString] JSONValue];
			if ([self validateDesktopMessageTwo: message] == NO) {
				[_delegate client: self didFailWithError: [self invalidServerResponseError]];
				return;
			}
			NSDictionary* payload = [message objectForKey: @"payload"];
			_key = [[_party generateKeyFromMessageTwo: payload] retain];
			if (_key == nil) {
				[_delegate client: self didFailWithError: [self errorWithCode: -1 localizedDescriptionKey: @""]]; // TODO: What to report here?
			} else {
				[self putMobileMessageThree];
			}
			break;
		}
		
		default: {
			[_delegate client: self didFailWithError: [self unexpectedServerResponseError]];
		}
	}
}

- (void) getDesktopMessageTwoDidFail: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#getDesktopMessageTwoDidFail: %@", request);
	[_delegate client: self didFailWithError: [request error]];
}

- (void) getDesktopMessageTwo
{
	ASIHTTPRequest* request = [ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]];
	if (request != nil) {
		[request setShouldAttemptPersistentConnection: NO];
		[request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[request setDelegate: self];
		[request addRequestHeader: @"If-None-Match" value: _etag];
		[request setDidFinishSelector: @selector(getDesktopMessageTwoDidFinish:)];
		[request setDidFailSelector: @selector(getDesktopMessageTwoDidFail:)];
		[_queue addOperation: request];
	}
}

#pragma mark -

- (void) putMobileMessageTwoDidFinish: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#putMobileMessageTwoDidFinish: %@", request);

	if ([request responseStatusCode] != 200) {
		[_delegate client: self didFailWithError: [self unexpectedServerResponseError]];
		return;
	}

	// Remember the etag
	[_etag release];
	_etag = [[[request responseHeaders] objectForKey: @"Etag"] retain];

	// Poll for the desktop's message two
	_pollRetryCount = 0;
	_timer = [[NSTimer scheduledTimerWithTimeInterval: ((NSTimeInterval) _pollDelay) / 1000.0
		target: self selector: @selector(getDesktopMessageTwo) userInfo: nil repeats: NO] retain];
}

- (void) putMobileMessageTwoDidFail: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#putMobileMessageTwoDidFail: %@", request);
	[_delegate client: self didFailWithError: [request error]];
}

- (void) putMobileMessageTwo: (NSDictionary*) one
{
	NSDictionary* message = [self messageWithType: @"receiver2" payload: [_party generateMessageTwoFromMessageOne: one]];
	NSString* json = [message JSONRepresentation];

	ASIHTTPRequest* request = [ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]];
	if (request != nil) {
		[request setShouldAttemptPersistentConnection: NO];
		[request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[request setRequestMethod: @"PUT"];
		[request setPostBody: [NSMutableData dataWithData: [json dataUsingEncoding: NSUTF8StringEncoding]]];
		[request setDelegate: self];
		[request setDidFinishSelector: @selector(putMobileMessageTwoDidFinish:)];
		[request setDidFailSelector: @selector(putMobileMessageTwoDidFail:)];
		[_queue addOperation: request];
	}	
}

#pragma mark -

- (void) getDesktopMessageOneDidFinish: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#getDesktopMessageOneDidFinish: %@", request);
	
	[_timer release];
	_timer = nil;

	switch ([request responseStatusCode]) {
		case 304: {
			if (_pollRetryCount < _pollRetries) {
				_timer = [[NSTimer scheduledTimerWithTimeInterval: ((NSTimeInterval) _pollInterval) / 1000.0
					target: self selector: @selector(getDesktopMessageOne) userInfo: nil repeats: NO] retain];
			} else {
				[_delegate client: self didFailWithError: [self timeoutError]];
			}
			break;
		}
		
		case 200: {
			NSDictionary* message = [[request responseString] JSONValue];
			if ([self validateDesktopMessageOne: message] == NO) {
				[_delegate client: self didFailWithError: [self invalidServerResponseError]];
			} else {
				NSDictionary* payload = [message objectForKey: @"payload"];
				[self putMobileMessageTwo: payload];
			}
			break;
		}
		
		default: {
			[_delegate client: self didFailWithError: [self unexpectedServerResponseError]];
		}
	}
}

- (void) getDesktopMessageOneDidFail: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#getDesktopMessageOneDidFail: %@", request);
	[_delegate client: self didFailWithError: [request error]];
}

- (void) getDesktopMessageOne
{
	ASIHTTPRequest* request = [ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]];
	if (request != nil) {
		[request setShouldAttemptPersistentConnection: NO];
		[request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[request setDelegate: self];
		[request addRequestHeader: @"If-None-Match" value: _etag];
		[request setDidFinishSelector: @selector(getDesktopMessageOneDidFinish:)];
		[request setDidFailSelector: @selector(getDesktopMessageOneDidFail:)];
		[request startAsynchronous];
	}
	_pollRetryCount++;
}

#pragma mark -

- (void) putMessageOneDidFinish: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#putMessageOneDidFinish: %@", request);

	if ([request responseStatusCode] != 200) {
		[_delegate client: self didFailWithError: [self unexpectedServerResponseError]];
		return;
	}

	[_delegate client: self didGenerateSecret: [NSString stringWithFormat: @"%@-%@-%@",
		[_secret substringToIndex: 4], [_secret substringFromIndex: 4], _channel]];

	// Remember the etag
	[_etag release];
	_etag = [[[request responseHeaders] objectForKey: @"Etag"] retain];
	
	// We have generated a secret and uploaded our message one. So now periodically poll to see if the other side has uploaded their message one.
	_pollRetryCount = 0;
	_timer = [[NSTimer scheduledTimerWithTimeInterval: ((NSTimeInterval) _pollDelay) / 1000.0
		target: self selector: @selector(getDesktopMessageOne) userInfo: nil repeats: NO] retain];
}

- (void) putMessageOneDidFail: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#putMessageOneDidFail: %@", request);
	[_delegate client: self didFailWithError: [request error]];
}

- (void) putMessageOne
{
	_party = [[JPAKEParty partyWithPassword: _secret modulusLength: 3072 signerIdentity: @"receiver" peerIdentity: @"sender"] retain];
	if (_party == nil) {
		[_delegate client: self didFailWithError: [self errorWithCode: -1 localizedDescriptionKey: @""]]; // TODO: What to report here?
		return;
	}
	
	NSDictionary* message = [self messageWithType: @"receiver1" payload: [_party generateMessageOne]];
	NSString* json = [message JSONRepresentation];

	ASIHTTPRequest* request = [ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]];
	if (request != nil) {
		[request setShouldAttemptPersistentConnection: NO];
		[request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[request setRequestMethod: @"PUT"];
		[request setPostBody: [NSMutableData dataWithData: [json dataUsingEncoding: NSUTF8StringEncoding]]];
		[request setDelegate: self];
		[request setDidFinishSelector: @selector(putMessageOneDidFinish:)];
		[request setDidFailSelector: @selector(putMessageOneDidFail:)];
		[_queue addOperation: request];
	}	
}

#pragma mark -

- (void) requestChannelDidFinish: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#requestChannelDidFinish: %@", request);

	if ([request responseStatusCode] != 200) {
		[_delegate client: self didFailWithError: [self unexpectedServerResponseError]];
		return;
	}

	_channel = [[request.responseString substringWithRange: NSMakeRange(1, [request.responseString length] - 2)] retain];
	_secret = [[NSString stringWithJPAKESecret] retain];
	
	// Generate message one and put it to the channel
	
	[self putMessageOne];
}

- (void) requestChannelDidFail: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#requestChannelDidFail: %@", request);
	[_delegate client: self didFailWithError: [request error]];
}

- (void) requestChannel
{
	NSURL* url = [NSURL URLWithString: @"/new_channel" relativeToURL: _server];

	ASIHTTPRequest* request = [ASIHTTPRequest requestWithURL: url];
	if (request != nil) {
		[request setShouldAttemptPersistentConnection: NO];
		[request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[request setDelegate: self];
		[request setDidFinishSelector: @selector(requestChannelDidFinish:)];
		[request setDidFailSelector: @selector(requestChannelDidFail:)];
		[_queue addOperation: request];
	}
}

#pragma mark -

- (void) start
{
	[ASIHTTPRequest setShouldUpdateNetworkActivityIndicator:NO];
	[self requestChannel];
}

- (void) cancel
{
	[_queue reset];
	
	if (_timer != nil) {
		[_timer invalidate];
		[_timer release];
		_timer = nil;
	}

	[_delegate clientDidCancel: self];
}

- (void) abort
{
	[_queue reset];
	
	if (_timer != nil) {
		[_timer invalidate];
		[_timer release];
		_timer = nil;
	}
}

@end
