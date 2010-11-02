// JPAKEReporter.m

#import "JPAKEReporter.h"
#import "ASIHTTPRequest.h"

@implementation JPAKEReporter

- (id) initWithServer: (NSURL*) server
{
	if ((self = [super init]) != nil) {
		_server = [server retain];
		_queue = [ASINetworkQueue new];
		[_queue go];
	}
	return self;
}

- (void) dealloc
{
	[_queue reset];
	[_queue release];
	[super dealloc];
}

#pragma mark -

- (void) requestFinished: (ASIHTTPRequest*) request
{
	NSLog(@"JPakeReporter#requestFinished:");
}
 
- (void) requestFailed: (ASIHTTPRequest*) request
{
	NSLog(@"JPakeReporter#requestFailed:");
}

- (void) reportCode: (NSInteger) code message: (NSString*) message
{
	NSURL* url = [NSURL URLWithString: @"/report" relativeToURL: _server];

	ASIHTTPRequest* request = [ASIHTTPRequest requestWithURL: url];
	if (request != nil)
	{
		[request setDelegate: self];
		[request setNumberOfTimesToRetryOnTimeout: 3];
		[request addRequestHeader: @"X-KeyExchange-Log-Code" value: [NSString stringWithFormat: @"%d", code]];
		[request addRequestHeader: @"X-KeyExchange-Log-Message" value: message];
		[_queue addOperation: request];
	}
}

@end
