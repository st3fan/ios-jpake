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

@implementation JPAKEClient

- (id) initWithServer: (NSURL*) server delegate: (id<JPAKEClientDelegate>) delegate
{
	if ((self = [super init]) != nil) {
		_server = [server retain];
		_delegate = delegate;
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
			NSLog(@"   Message is %@", message);
			NSDictionary* payload = [message objectForKey: @"payload"];
			NSData* iv = [[NSData alloc] initWithBase64EncodedString: [payload objectForKey: @"iv"]];
			NSData* ct = [[NSData alloc] initWithBase64EncodedString: [payload objectForKey: @"ciphertext"]];
			NSData* plaintext = [[NSData alloc] initWithAESEncryptedData: ct key: _key iv: iv];
			NSString* json = [[NSString alloc] initWithData: plaintext encoding: NSUTF8StringEncoding];
			[_delegate client: self didReceivePayload: [json JSONValue]];
			break;
		}
		
		default: {
			[_delegate client: self didFailWithError: nil];
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
		[_delegate client: self didFailWithError: nil];
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

	NSDictionary* message = [self messageWithType: @"s3" payload: [[[_key SHA256Hash] SHA256Hash] base16Encoding]];
	NSString* json = [message JSONRepresentation];
	NSLog(@"   Putting %@", json);
	NSMutableData* data = [NSMutableData dataWithData: [json dataUsingEncoding: NSUTF8StringEncoding]];

	_request = [[ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]] retain];
	if (_request != nil) {
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
			NSDictionary* payload = [message objectForKey: @"payload"];
			_key = [[_party generateKeyFromMessageTwo: payload] retain];
			[self putMobileMessageThree];
			break;
		}
		
		default: {
			[_delegate client: self didFailWithError: nil];
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
		[_delegate client: self didFailWithError: nil];
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
	NSDictionary* message = [self messageWithType: @"s2" payload: [_party generateMessageTwoFromMessageOne: one]];
	NSString* json = [message JSONRepresentation];

	_request = [[ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]] retain];
	if (_request != nil) {
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
			NSDictionary* payload = [message objectForKey: @"payload"];
			[self putMobileMessageTwo: payload];
			break;
		}
		
		default: {
			[_delegate client: self didFailWithError: nil];
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
		[_delegate client: self didFailWithError: nil];
		return;
	}

	[_delegate client: self didGenerateSecret: [NSString stringWithFormat: @"%@%@", _password, _channel]];

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
	_party = [[JPAKEParty partyWithPassword: _password modulusLength: 1024 signerIdentity: @"Mobile" peerIdentity: @"Desktop"] retain];
	if (_party == nil) {
		[_delegate client: self didFailWithError: nil];
		return;
	}
	
	NSDictionary* message = [self messageWithType: @"s1" payload: [_party generateMessageOne]];
	NSString* json = [message JSONRepresentation];

	_request = [[ASIHTTPRequest requestWithURL: [NSURL URLWithString: [NSString stringWithFormat: @"/%@", _channel] relativeToURL: _server]] retain];
	if (_request != nil) {
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

	_channel = [[request.responseString substringWithRange: NSMakeRange(1, [request.responseString length] - 2)] retain];
	_password = @"Test";
	
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
