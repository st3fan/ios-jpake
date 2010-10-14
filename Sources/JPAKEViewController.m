// JPAKEViewController.m

#import "JPAKEViewController.h"

@implementation JPAKEViewController

@synthesize statusLabel = _statusLabel;
@synthesize passwordLabel = _passwordLabel;

@synthesize server = _server;
@synthesize delegate = _delegate;

- (void) viewDidLoad
{
	_client = [[JPAKEClient alloc] initWithServer: _server delegate: self];
	[_client start];
}

#pragma mark -

- (IBAction) cancel
{
	[_client cancel];
}

#pragma mark -

- (void) client: (JPAKEClient*) client didGenerateSecret: (NSString*) secret
{
	_passwordLabel.text = secret;
}

- (void) client: (JPAKEClient*) client didFailWithError: (NSError*) error
{
	[_delegate JPAKEViewController: self didFailWithError: error];
}

- (void) client: (JPAKEClient*) client didReceivePayload: (id) payload
{
	[_delegate JPAKEViewController: self didFinishWithMessage: payload];
}

@end
