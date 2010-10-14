// JPAKEClient.m

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

@implementation JPAKEClient (Private)

@end


@implementation JPAKEClient

- (id) initWithServer: (NSURL*) server delegate: (id<JPAKEClientDelegate>) delegate
{
	if ((self = [super init]) != nil) {
		_server = [server retain];
		_delegate = delegate;
		_clientIdentifier = [[NSString stringWithJPAKEClientIdentifier] retain];
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
	
	NSDictionary* payload = [message objectForKey: @"payload"];
	if (payload == nil || [payload isKindOfClass: [NSDictionary class]] == NO) {
		return NO;
	}
	
	NSDictionary* zkp_x1 = [payload objectForKey: @"zkp_x1"];	
	if (zkp_x1 == nil || [zkp_x1 isKindOfClass: [NSDictionary class]] == NO) {
		return NO;
	}
	
	NSDictionary* zkp_x2 = [payload objectForKey: @"zkp_x2"];
	if (zkp_x2 == nil || [zkp_x2 isKindOfClass: [NSDictionary class]] == NO) {
		return NO;
	}
	
	return YES;
}

- (BOOL) validateDesktopMessageTwo: (NSDictionary*) message
{
	if ([self validateBasicMessage: message ofType: @"sender2"] == NO) {
		return NO;
	}

	return YES;
}

- (BOOL) validateDesktopMessageThree: (NSDictionary*) message
{
	if ([self validateBasicMessage: message ofType: @"sender3"] == NO) {
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
		[_request addRequestHeader: @"X-Weave-ClientID" value: _clientIdentifier];
		[_request setDelegate: self];
		[_request setDidFinishSelector: @selector(deleteChannelDidFinish:)];
		[_request setDidFailSelector: @selector(deleteChannelDidFail:)];
		[_request startAsynchronous];
	}		
}

#pragma mark -

- (void) getDesktopMessageThreeDidFinish: (ASIHTTPRequest*) request
{
	NSLog(@"JPAKEClient#getDesktopMessageThreeDidFinish: %@", request);

	switch ([request responseStatusCode]) {
		case 304: {
			[_timer release];
			_timer = [[NSTimer scheduledTimerWithTimeInterval: 5.0 target: self selector: @selector(getDesktopMessageThree) userInfo: nil repeats: NO] retain];
			break;
		}
		
		case 200: {
			NSDictionary* message = [[request responseString] JSONValue];
			if ([self validateDesktopMessageThree: message] == NO) {
				[_delegate client: self didFailWithError: [self invalidServerResponseError]];
				return;
			}
			NSLog(@"   Message is %@", message);
			NSDictionary* payload = [message objectForKey: @"payload"];
			NSData* iv = [[[NSData alloc] initWithBase64EncodedString: [payload objectForKey: @"IV"]] autorelease];
			NSData* ct = [[[NSData alloc] initWithBase64EncodedString: [payload objectForKey: @"ciphertext"]] autorelease];
			NSData* plaintext = [[[NSData alloc] initWithAESEncryptedData: ct key: _key iv: iv] autorelease];
			NSString* json = [[[NSString alloc] initWithData: plaintext encoding: NSUTF8StringEncoding] autorelease];
			[_delegate client: self didReceivePayload: [json JSONValue]];
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
		[_request addRequestHeader: @"X-Weave-ClientID" value: _clientIdentifier];
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
	_timer = [[NSTimer scheduledTimerWithTimeInterval: 3.0 target: self selector: @selector(getDesktopMessageThree) userInfo: nil repeats: NO] retain];
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
		[_request addRequestHeader: @"X-Weave-ClientID" value: _clientIdentifier];
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
	
	switch ([request responseStatusCode]) {
		case 304: {
			[_timer release];
			_timer = [[NSTimer scheduledTimerWithTimeInterval: 5.0 target: self selector: @selector(getDesktopMessageTwo) userInfo: nil repeats: NO] retain];
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
				return;
			}
			[self putMobileMessageThree];
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
		[_request addRequestHeader: @"X-Weave-ClientID" value: _clientIdentifier];
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
	_timer = [[NSTimer scheduledTimerWithTimeInterval: 3.0 target: self selector: @selector(getDesktopMessageTwo) userInfo: nil repeats: NO] retain];
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
		[_request addRequestHeader: @"X-Weave-ClientID" value: _clientIdentifier];
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
	
	switch ([request responseStatusCode]) {
		case 304: {
			[_timer release];
			_timer = [[NSTimer scheduledTimerWithTimeInterval: 5.0 target: self selector: @selector(getDesktopMessageOne) userInfo: nil repeats: NO] retain];
			break;
		}
		
		case 200: {
			NSDictionary* message = [[request responseString] JSONValue];
			if ([self validateDesktopMessageOne: message] == NO) {
				[_delegate client: self didFailWithError: [self invalidServerResponseError]];
				return;
			}
			NSDictionary* payload = [message objectForKey: @"payload"];
			[self putMobileMessageTwo: payload];
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
		[_request addRequestHeader: @"X-Weave-ClientID" value: _clientIdentifier];
		[_request setDelegate: self];
		[_request addRequestHeader: @"If-None-Match" value: _etag];
		[_request setDidFinishSelector: @selector(getDesktopMessageOneDidFinish:)];
		[_request setDidFailSelector: @selector(getDesktopMessageOneDidFail:)];
		[_request startAsynchronous];
	}
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
	_timer = [[NSTimer scheduledTimerWithTimeInterval: 5.0 target: self selector: @selector(getDesktopMessageOne) userInfo: nil repeats: NO] retain];
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
		[_request addRequestHeader: @"X-Weave-ClientID" value: _clientIdentifier];
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
		[_request addRequestHeader: @"X-Weave-ClientID" value: _clientIdentifier];
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
