// JPAKEPartyTest.h

#import <SenTestingKit/SenTestingKit.h>

@interface JPAKEPartyTest : SenTestCase {

}

- (void) testPasswordExchange1024;
- (void) testPasswordExchangeWithWrongPasswords1024;

- (void) testPasswordExchange2048;
- (void) testPasswordExchangeWithWrongPasswords2048;

- (void) testPasswordExchange3072;
- (void) testPasswordExchangeWithWrongPasswords3072;

@end
