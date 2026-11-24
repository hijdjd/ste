#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

static double retFuture(id s,SEL c){return 4102444799.0;}
static BOOL retYES(id s,SEL c){return YES;}
static BOOL retNO(id s,SEL c){return NO;}
static void noop(id s,SEL c){}

static BOOL inApp(Class K){
  Dl_info di; if(!dladdr((__bridge void*)K,&di)||!di.dli_fname) return NO;
  NSString*p=[NSString stringWithUTF8String:di.dli_fname];
  return [p containsString:@"Podcasts.app"]||[p containsString:@"StarbucksSTE"];
}

// _onLogin 的原实现（若为空则直接置状态）
static void forceActivate(id selfObj){
  // 直接给关键属性赋值，跳过网络验证
  @try{
    if([selfObj respondsToSelector:NSSelectorFromString(@"setCoreLeaseExpiresAt:")]) [selfObj setValue:@(4102444799.0) forKey:@"coreLeaseExpiresAt"];
    if([selfObj respondsToSelector:NSSelectorFromString(@"setFeatureLeaseExpiresAt:")]) [selfObj setValue:@(4102444799.0) forKey:@"featureLeaseExpiresAt"];
    if([selfObj respondsToSelector:NSSelectorFromString(@"setVipExpireTime:")]) [selfObj setValue:@(4102444799.0) forKey:@"vipExpireTime"];
    if([selfObj respondsToSelector:NSSelectorFromString(@"setExpireTimer:")]) @try{[selfObj setValue:@(4102444799.0) forKey:@"expireTimer"];}@catch(id e){}
    // 通知 UI 刷新
    [[NSNotificationCenter defaultCenter] postNotificationName:@"com.via.pro.hj.authorization.changed" object:nil];
  }@catch(id e){}
}

static void my_onLogin(id selfObj,SEL c,id arg){
  NSLog(@"[STE] _onLogin hooked");
  forceActivate(selfObj);
}

static void sweep(void){
  int n=objc_getClassList(NULL,0);
  Class*cls=(Class*)calloc(n,sizeof(Class)); n=objc_getClassList(cls,n);
  for(int i=0;i<n;i++){
    Class K=cls[i]; if(!inApp(K)) continue;
    unsigned mc=0; Method*ms=class_copyMethodList(K,&mc);
    for(unsigned j=0;j<mc;j++){
      SEL sel=method_getName(ms[j]); const char*sn=sel_getName(sel); NSString*s=[NSString stringWithUTF8String:sn];
      const char*te=method_getTypeEncoding(ms[j]);
      if([s isEqualToString:@"_onLogin"]||[s isEqualToString:@"onLogin"]||[s isEqualToString:@"loginButtonTapped:"]||[s isEqualToString:@"onLogin:"]){
        method_setImplementation(ms[j],(IMP)my_onLogin);
        NSLog(@"[STE] patched %s",sn);
      }
      else if((te[0]=='c'||te[0]=='B') && ([sn[0]=='_'?sn+1:sn) && (
          [s hasPrefix:@"responseMessageIndicatesLoginFailure"]||[s hasPrefix:@"responseIndicatesSessionInvalid"]||
          [s hasPrefix:@"messageMeansInvalidSession"]||[s hasPrefix:@"messageIndicatesSessionInvalid"]||
          [s hasPrefix:@"isExpired"]||[s hasPrefix:@"isInvalid"])){
        method_setImplementation(ms[j],(IMP)retNO);
      }
      else if((te[0]=='c'||te[0]=='B') && ([s hasPrefix:@"hasValid"]||[s hasPrefix:@"isValid"]||
          [s hasPrefix:@"isVIP"]||[s hasPrefix:@"isAuthorized"]||[s hasPrefix:@"isActivated"]||
          [s hasPrefix:@"hasSavedCard"])){
        method_setImplementation(ms[j],(IMP)retYES);
      }
      if(([s isEqualToString:@"coreLeaseExpiresAt"]||[s isEqualToString:@"featureLeaseExpiresAt"]||
          [s isEqualToString:@"vipExpireTime"]||[s isEqualToString:@"secureExpiresAt"]) && te[0]=='d')
        method_setImplementation(ms[j],(IMP)retFuture);
      if([s hasPrefix:@"_showExpiredAlert"]&&te[0]=='v') method_setImplementation(ms[j],(IMP)noop);
    }
    free(ms);
  }
  free(cls);
}

__attribute__((constructor)) static void ste_init(void){
  sweep();
  NSLog(@"[STE] init done");
}
