//
//  ViewController.m
//  RSA1024_ECB_PKCS1Padding
//
//  Created by syt on 2019/12/5.
//  Copyright © 2019 syt. All rights reserved.
//

#import "ViewController.h"

#import "RSAManager.h"

/**
 此公钥是后台返回的
 */
#define k_Public_Key     @"30819f300d06092a864886f70d010101050003818d0030818902818100cbb3c750d2e5dcc57a1ea26bf6237922a368fb61c4c78c4807a6640988f89df6740d108599ee86382fa0c95f59321665f80048bc318ccf54fc807a21ea4c6daab6011db965cdfc88be8ca3611563bebef02e86f17816cd4d7bd78c5dae6b36fa33520be75af0dbfd31efcfbc5d2a07f1f4b58fa0b6cc1e7999211363ba9531350203010001"

@interface ViewController ()

// 加密按钮
@property (nonatomic, strong) UIButton *rsaButton;
// 需要加密的内容
@property (nonatomic, strong) UITextField *passWdText;
// 加密后的文本
@property (nonatomic, strong) UITextView *textView;


@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    self.view.backgroundColor = UIColor.whiteColor;
    [self createSubViews];
}

- (void)createSubViews
{
    [self.view addSubview:self.passWdText];
    [self.view addSubview:self.rsaButton];
    [self.view addSubview:self.textView];
}






#pragma mark - rsaButtonAction
- (void)rsaButtonAction
{
    [self.view endEditing:YES];
    if ([self checkPassWd]) {
        NSString *result = [RSAManager encryptRSA:self.passWdText.text PublicKey:k_Public_Key];
        self.textView.text = [NSString stringWithFormat:@"%@", result];
    }
}

- (BOOL)checkPassWd
{
    if ([self.passWdText.text isEqualToString:@""] || self.passWdText.text.length == 0) {
        [self showAlertVC];
        return NO;
    }
    return YES;
}

- (void)showAlertVC
{
    UIAlertController *alertVC = [UIAlertController alertControllerWithTitle:@"要加密的内容不能为空" message:nil preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:alertVC animated:YES completion:nil];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [alertVC dismissViewControllerAnimated:YES completion:nil];
    });
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event
{
    [self.view endEditing:YES];
}









#pragma mark - lazy loading

- (UITextField *)passWdText
{
    if (!_passWdText) {
        _passWdText = [[UITextField alloc] initWithFrame:CGRectMake(20, 100, [UIScreen mainScreen].bounds.size.width - 40, 40)];
        _passWdText.backgroundColor = UIColor.whiteColor;
        _passWdText.layer.masksToBounds = YES;
        _passWdText.layer.cornerRadius = 5;
        _passWdText.layer.borderWidth = 1;
        _passWdText.layer.borderColor = UIColor.lightGrayColor.CGColor;
        _passWdText.placeholder = @"请输入需要加密的内容";
        _passWdText.textColor = UIColor.blackColor;
        _passWdText.keyboardType = UIKeyboardTypeNumberPad;
        _passWdText.font = [UIFont systemFontOfSize:16];
    }
    return _passWdText;
}

- (UIButton *)rsaButton
{
    if (!_rsaButton) {
        _rsaButton = [UIButton buttonWithType:UIButtonTypeCustom];
        _rsaButton.frame = CGRectMake(20, CGRectGetMaxY(self.passWdText.frame) + 30, [UIScreen mainScreen].bounds.size.width - 40, 40);
        _rsaButton.backgroundColor = UIColor.orangeColor;
        _rsaButton.layer.masksToBounds = YES;
        _rsaButton.layer.cornerRadius = 10;
        [_rsaButton setTitle:@"加密" forState:UIControlStateNormal];
        _rsaButton.titleLabel.font = [UIFont systemFontOfSize:16];
        [_rsaButton addTarget:self action:@selector(rsaButtonAction) forControlEvents:UIControlEventTouchUpInside];
    }
    return _rsaButton;
}

- (UITextView *)textView
{
    if (!_textView) {
        _textView = [[UITextView alloc] initWithFrame:CGRectMake(20, CGRectGetMaxY(self.rsaButton.frame) + 50, [UIScreen mainScreen].bounds.size.width - 40, 200)];
        _textView.editable = NO;
        _textView.bounces = NO;
        _textView.textColor = UIColor.redColor;
        _textView.font = [UIFont systemFontOfSize:14];
        _textView.layer.masksToBounds = YES;
        _textView.layer.cornerRadius = 8;
        _textView.layer.borderWidth = 1;
        _textView.layer.borderColor = UIColor.lightGrayColor.CGColor;
    }
    return _textView;
}

@end
