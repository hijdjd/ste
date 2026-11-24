#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <UIKit/UIKit.h>

static BOOL retYES(id s,SEL c){return YES;}
static BOOL retNO(id s,SEL c){return NO;}
static double retFuture(id s,SEL c){return 4102444799.0;}
static id retDummy(id s,SEL c){return @"qvip999999999";}
static void noop(id s,SEL c){}

// yy 暴露的真实授权方法名（精确）
static NSSet *gFail(void){static NSSet*s;static dispatch_once_t o;dispatch_once(&o,^{
  s=[NSSet setWithArray:@[@"responseMessageIndicatesLoginFailure:",@"responseIndicatesSessionInvalid:error:",
    @"messageMeansInvalidSession:",@"messageIndicatesSessionInvalid:",@"responseMessageIndicatesLoginFailure",
    @"isExpired",@"isInvalid"]];
});return s;}

static void sweep(void){
  int n=objc_getClassList(NULL,0);
  Class*cls=(Class*)calloc(n,sizeof(Class)); n=objc_getClassList(cls,n);
  NSMutableString*dump=[NSMutableString string];
  for(int i=0;i<n;i++){
    Class K=cls[i];
    const char*cn=class_getName(K); if(!cn) continue;
    NSString*clsname=[NSString stringWithUTF8String:cn];
    // 只处理 biz 类：名字含 QX/F5/Core/Gate/License/Login/Verify/Card 或无前缀但方法命中时处理
    BOOL bizInterest = ([clsname containsString:@"Core"]||[clsname containsString:@"QX"]||
      [clsname containsString:@"F5"]||[clsname containsString:@"Gate"]||[clsname containsString:@"License"]||
      [clsname containsString:@"Login"]||[clsname containsString:@"Verify"]||[clsname containsString:@"Card"]||
      [clsname containsString:@"Auth"]||[clsname containsString:@"Vip"]||[clsname containsString:@"VIP"]);
    unsigned mc=0; Method*ms=class_copyMethodList(K,&mc);
    for(unsigned j=0;j<mc;j++){
      SEL sel=method_getName(ms[j]); const char*sn=sel_getName(sel); NSString*s=[NSString stringWithUTF8String:sn];
      const char*te=method_getTypeEncoding(ms[j]);
      // dump 所有与授权相关方法（不限类，保证不漏）
      if([s containsString:@"Login"]||[s containsString:@"Card"]||[s containsString:@"Lease"]||
         [s containsString:@"Token"]||[s containsString:@"Vip"]||[s containsString:@"vip"]||
         [s containsString:@"Expire"]||[s containsString:@"expire"]||[s containsString:@"Valid"]||
         [s containsString:@"Authoriz"]||[s containsString:@"Session"]||[s containsString:@"Ticket"]||
         [s containsString:@"Gate"]||[s containsString:@"verify"]||[s containsString:@"Verify"]){
        [dump appendFormat:@"%@ - %s %s\n",clsname,sn,te];
      }
      BOOL isBool=(te[0]=='c'||te[0]=='B');
      BOOL isDouble=(te[0]=='d');
      BOOL isVoid=(te[0]=='v');
      // 失败判定 -> NO
      if(isBool && ([s isEqualToString:@"responseMessageIndicatesLoginFailure:"]||
                    [s hasPrefix:@"responseIndicatesSessionInvalid"]||
                    [s hasPrefix:@"messageMeansInvalidSession"]||
                    [s hasPrefix:@"messageIndicatesSessionInvalid"]||
                    [s hasPrefix:@"isExpired"]||[s hasPrefix:@"isInvalid"]||
                    [s hasPrefix:@"isBanned"]||[s hasPrefix:@"isFrozen"])){
        method_setImplementation(ms[j],(IMP)retNO);
      }
      // 有租约/授权 -> YES  (bsupx_c_has_lease 是C函数,这里命中ObjC等价)
      if(isBool && ([s hasPrefix:@"hasValid"]||[s hasPrefix:@"hasLease"]||[s hasPrefix:@"hasSavedCard"]||
                    [s hasPrefix:@"isValid"]||[s hasPrefix:@"isVIP"]||[s hasPrefix:@"isVip"]||
                    [s hasPrefix:@"isAuthorized"]||[s hasPrefix:@"isActivated"]||
                    [s hasPrefix:@"hasValidCore"]||[s hasPrefix:@"hasValidFeature"])){
        method_setImplementation(ms[j],(IMP)retYES);
      }
      // 到期时间 -> 2099
      if(isDouble && ([s isEqualToString:@"coreLeaseExpiresAt"]||[s isEqualToString:@"featureLeaseExpiresAt"]||
                    [s isEqualToString:@"vipExpireTime"]||[s isEqualToString:@"secureExpiresAt"]||
                    [s containsString:@"ExpiresAt"]||[s containsString:@"ExpireTime"])){
        method_setImplementation(ms[j],(IMP)retFuture);
      }
      // 卡密/票据返回非空
      if(([s isEqualToString:@"activeCard"]||[s isEqualToString:@"savedCard"]||[s isEqualToString:@"_ticket"]||
          [s isEqualToString:@"coreToken"]||[s isEqualToString:@"featureToken"]) && te[0]=='@'){
        method_setImplementation(ms[j],(IMP)retDummy);
      }
      // 到期退出 -> noop
      if(isVoid && [s hasPrefix:@"_showExpiredAlert"]) method_setImplementation(ms[j],(IMP)noop);
    }
    free(ms);
  }
  free(cls);
  [dump writeToFile:@"/var/mobile/stehook_dump.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
  NSLog(@"[STE] sweep done, classes=%d",n);
}

__attribute__((constructor)) static void ste_init(void){ sweep(); }
