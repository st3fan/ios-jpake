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
 * The Original Code is Weave.
 *
 * The Initial Developer of the Original Code is
 * the Mozilla Foundation.
 * Portions created by the Initial Developer are Copyright (C) 2010
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
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

// TODO:
//
//    Comments
//    keep _request around
//    implement cancel
//    clean up properly
//    better validation of messages
//    better handling of failure
//    error codes
//    delegate method that updates progress
//

#import "NSData+AES.h"
#import "NSData+Base64.h"
#import "NSData+SHA256.h"

#import "JPAKEClient.h"
#import "JSON.h"

@implementation NSString (JPAKE)

/**
 * Generate a JPAKE Secret. Currently implemented as 4 random characters.
 */

+ (NSString*) stringWithJPAKESecret
{
	NSMutableString* secret = [NSMutableString stringWithCapacity: 4];
	
	srandomdev();
	
	for (int i = 0; i < 8; i++) {
		switch (random() % 2) {
			case 0:
				[secret appendFormat: @"%c", '0' + (random() % 10)];
				break;
			case 1:
				[secret appendFormat: @"%c", 'a' + (random() % 26)];
				break;
		}
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

- (id) initWithServer: (NSURL*) server delegate: (id<JPAKEClientDelegate>) delegate
{
	if ((self = [super init]) != nil) {
		_server = [server retain];
		_delegate = delegate;
		_clientIdentifier = [[NSString stringWithJPAKEClientIdentifier] retain];
		_pollRetries = 60;
		_pollInterval = 1000;
	}
	
	return self;
}

- (void) dealloc
{
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
	
	_request = [[ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]] retain];
	if (_request != nil) {
		[_request setRequestMethod: @"DELETE"];
		[_request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[_request setDelegate: self];
		[_request setDidFinishSelector: @selector(deleteChannelDidFinish:)];
		[_request setDidFailSelector: @selector(deleteChannelDidFail:)];
		[_request startAsynchronous];
	}		
}

#pragma mark -

- (NSString*) decryptPayload: (NSDictionary*) payload withKey: (NSData*) key error: (NSError**) error
{
	NSData* iv = [[[NSData alloc] initWithBase64EncodedString: [payload objectForKey: @"IV"]] autorelease];
	if (iv == nil || [iv length] != 16) {
		*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		return nil;
	}
	
	NSData* ciphertext = [[[NSData alloc] initWithBase64EncodedString: [payload objectForKey: @"ciphertext"]] autorelease];
	if (ciphertext == nil || [ciphertext length] == 0) {
		*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		return nil;
	}
	
	NSData* hmac = [[[NSData alloc] initWithBase16EncodedString: [payload objectForKey: @"hmac"]] autorelease];
	if (hmac == nil || [hmac length] != 32) {
		*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		return nil;
	}

	NSData* cipherTextData = [[payload objectForKey: @"ciphertext"] dataUsingEncoding: NSASCIIStringEncoding];

	NSData* hmacValue = [cipherTextData HMACSHA256WithKey: key];
	if (hmacValue == nil || [hmac isEqualToData: hmacValue] == NO) {
		*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		return nil;
	}
	
	NSData* plaintext = [[[NSData alloc] initWithAESEncryptedData: ciphertext key: _key iv: iv] autorelease];
	if (plaintext == nil) {
		*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
		return nil;
	}

	NSString* json = [[[NSString alloc] initWithData: plaintext encoding: NSUTF8StringEncoding] autorelease];
	if (json == nil) {
		*error = [self errorWithCode: kJPAKEClientErrorInvalidCryptoPayload localizedDescriptionKey: @"The message contains invalid crypto payload"];
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
	
	_request = [[ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]] retain];
	if (_request != nil) {
		[_request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[_request addRequestHeader: @"If-None-Match" value: _etag];
		[_request setDelegate: self];
		[_request setDidFinishSelector: @selector(getDesktopMessageThreeDidFinish:)];
		[_request setDidFailSelector: @selector(getDesktopMessageThreeDidFail:)];
		[_request startAsynchronous];
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
	_timer = [[NSTimer scheduledTimerWithTimeInterval: ((NSTimeInterval) _pollInterval) / 1000.0
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

	_request = [[ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]] retain];
	if (_request != nil) {
		[_request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[_request setRequestMethod: @"PUT"];
		[_request setPostBody: data];
		[_request setDelegate: self];
		[_request setDidFinishSelector: @selector(putMobileMessageThreeDidFinish:)];
		[_request setDidFailSelector: @selector(putMobileMessageThreeDidFail:)];
		[_request startAsynchronous];
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
	_request = [[ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]] retain];
	if (_request != nil) {
		[_request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[_request setDelegate: self];
		[_request addRequestHeader: @"If-None-Match" value: _etag];
		[_request setDidFinishSelector: @selector(getDesktopMessageTwoDidFinish:)];
		[_request setDidFailSelector: @selector(getDesktopMessageTwoDidFail:)];
		[_request startAsynchronous];
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
	_timer = [[NSTimer scheduledTimerWithTimeInterval: ((NSTimeInterval) _pollInterval) / 1000.0
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

	_request = [[ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]] retain];
	if (_request != nil) {
		[_request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[_request setRequestMethod: @"PUT"];
		[_request setPostBody: [NSMutableData dataWithData: [json dataUsingEncoding: NSUTF8StringEncoding]]];
		[_request setDelegate: self];
		[_request setDidFinishSelector: @selector(putMobileMessageTwoDidFinish:)];
		[_request setDidFailSelector: @selector(putMobileMessageTwoDidFail:)];
		[_request startAsynchronous];
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
	_request = [[ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]] retain];
	if (_request != nil) {
		[_request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[_request setDelegate: self];
		[_request addRequestHeader: @"If-None-Match" value: _etag];
		[_request setDidFinishSelector: @selector(getDesktopMessageOneDidFinish:)];
		[_request setDidFailSelector: @selector(getDesktopMessageOneDidFail:)];
		[_request startAsynchronous];
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
	_timer = [[NSTimer scheduledTimerWithTimeInterval: ((NSTimeInterval) _pollInterval) / 1000.0
		target: self selector: @selector(getDesktopMessageOne) userInfo: nil repeats: NO] retain];
}

- (void) putMessageOneDidFail: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#putMessageOneDidFail: %@", request);
	[_delegate client: self didFailWithError: [request error]];
}

- (void) putMessageOne
{
	_party = [[JPAKEParty partyWithPassword: _secret modulusLength: 1024 signerIdentity: @"receiver" peerIdentity: @"sender"] retain];
	if (_party == nil) {
		[_delegate client: self didFailWithError: [self errorWithCode: -1 localizedDescriptionKey: @""]]; // TODO: What to report here?
		return;
	}
	
	NSDictionary* message = [self messageWithType: @"receiver1" payload: [_party generateMessageOne]];
	NSString* json = [message JSONRepresentation];

	_request = [[ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]] retain];
	if (_request != nil) {
		[_request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[_request setRequestMethod: @"PUT"];
		[_request setPostBody: [NSMutableData dataWithData: [json dataUsingEncoding: NSUTF8StringEncoding]]];
		[_request setDelegate: self];
		[_request setDidFinishSelector: @selector(putMessageOneDidFinish:)];
		[_request setDidFailSelector: @selector(putMessageOneDidFail:)];
		[_request startAsynchronous];
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
		
	[_request release];
	_request = nil;
	
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

	_request = [[ASIHTTPRequest requestWithURL: url] retain];
	if (_request != nil) {
		[_request addRequestHeader: @"X-KeyExchange-Id" value: _clientIdentifier];
		[_request setDelegate: self];
		[_request setDidFinishSelector: @selector(requestChannelDidFinish:)];
		[_request setDidFailSelector: @selector(requestChannelDidFail:)];
		[_request startAsynchronous];
	}
}

#pragma mark -

- (void) start
{
	[self requestChannel];
}

- (void) cancel
{
}

@end
