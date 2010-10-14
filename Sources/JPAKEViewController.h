// JPAKEViewController.h

#import <UIKit/UIKit.h>

#import "JPAKEClient.h"

@class JPAKEViewController;

@protocol JPAKEViewControllerDelegate
- (void) JPAKEViewController: (JPAKEViewController*) vc didFinishWithMessage: (id) message;
- (void) JPAKEViewController: (JPAKEViewController*) vc didFailWithError: (NSError*) error;
@end

@interface JPAKEViewController : UIViewController <JPAKEClientDelegate> {
  @private
	UILabel* _passwordLabel;
	UILabel* _statusLabel;
  @private
    NSURL* _server;
	id<JPAKEViewControllerDelegate> _delegate;
  @private
	JPAKEClient* _client;
}

@property (nonatomic,assign) IBOutlet UILabel* passwordLabel;
@property (nonatomic,assign) IBOutlet UILabel* statusLabel;

@property (nonatomic,retain) NSURL* server;
@property (nonatomic,assign) id<JPAKEViewControllerDelegate> delegate;

- (IBAction) cancel;

@end
