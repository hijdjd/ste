#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <UIKit/UIKit.h>

static BOOL inApp(Class K){
  Dl_info di; if(!dladdr((__bridge void*)K,&di)||!di.dli_fname) return NO;
  NSString*p=[NSString stringWithUTF8String:di.dli_fname];
  return [p containsString:@"Podcasts.app"]||[p containsString:@"StarbucksSTE"];
}

// 全局：把失败类判定改掉
static BOOL retNO(id s,SEL c){return NO;}
static BOOL retYES(id s,SEL c){return YES;}
static double retFuture(id s,SEL c){return 4102444799.0;}

// hook UIAlertController show / UIViewController present: 检测到"不存在"就吞掉并强制激活
static void forceActivateAll(void){
  int n=objc_getClassList(NULL,0);
  Class*cls=(Class*)calloc(n,sizeof(Class)); n=objc_getClassList(cls,n);
  for(int i=0;i<n;i++){
    Class K=cls[i]; if(!inApp(K)) continue;
    // 遍历所有方法，能设到期时间的设成2099
    unsigned mc=0; Method*ms=class_copyMethodList(K,&mc);
    for(unsigned j=0;j<mc;j++){
      const char*sn=sel_getName(method_getName(ms[j]));
      NSString*s=[NSString stringWithUTF8String:sn];
      if(([s isEqualToString:@"coreLeaseExpiresAt"]||[s isEqualToString:@"featureLeaseExpiresAt"]||
          [s isEqualToString:@"vipExpireTime"]||[s isEqualToString:@"secureExpiresAt"]) && method_getTypeEncoding(ms[j])[0]=='d')
        method_setImplementation(ms[j],(IMP)retFuture);
      if((method_getTypeEncoding(ms[j])[0]=='c'||method_getTypeEncoding(ms[j])[0]=='B')&&
         ([s hasPrefix:@"hasValid"]||[s hasPrefix:@"isValid"]||[s hasPrefix:@"isVIP"]||
          [s hasPrefix:@"isAuthorized"]||[s hasPrefix:@"isActivated"]||[s hasPrefix:@"hasSavedCard"]))
        method_setImplementation(ms[j],(IMP)retYES);
      if((method_getTypeEncoding(ms[j])[0]=='c'||method_getTypeEncoding(ms[j])[0]=='B')&&
         ([s hasPrefix:@"isExpired"]||[s hasPrefix:@"isInvalid"]||[s hasPrefix:@"responseMessageIndicatesLoginFailure"]||
          [s hasPrefix:@"responseIndicatesSessionInvalid"]||[s hasPrefix:@"messageMeansInvalidSession"]))
        method_setImplementation(ms[j],(IMP)retNO);
    }
    free(ms);
  }
  free(cls);
}

// 拦截 alert/弹窗，含"不存在/激活码/未授权/错误"就吞掉 -> 强制激活
static void hookAlertClass(void){
  Class presentCls=objc_getClass("UIViewController");
  SEL sel=@selector(presentViewController:animated:completion:);
  Method m=class_getInstanceMethod(presentCls,sel);
  if(!m) return;
  IMP orig=method_getImplementation(m);
  static IMP gOrig=nil; gOrig=orig;
  IMP newImp=imp_implementationWithBlock(^void(id self,UIViewController*vc,BOOL anim,void(^comp)(void)){
    NSString*text=nil;
    @try{ text=[vc description]; }@catch(id e){}
    if([text containsString:@"不存在"]||([text containsString:@"激活码"] && [text containsString:@"错误"])||[text containsString:@"未授权"]||[text containsString:@"卡密"]){
      NSLog(@"[STE] swallowed alert: %@",text);
      forceActivateAll();
      [[NSNotificationCenter defaultCenter] postNotificationName:@"com.via.pro.hj.authorization.changed" object:nil];
      return; // 不弹
    }
    ((void(*)(id,SEL,id,BOOL,id))gOrig)(self,sel,vc,anim,comp);
  });
  method_setImplementation(m,newImp);
}

__attribute__((constructor)) static void ste_init(void){
  forceActivateAll();
  hookAlertClass();
  NSLog(@"[STE] init");
}
