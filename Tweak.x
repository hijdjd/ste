// Starbucks-STE auth bypass — 运行时遍历类，替换所有授权判定 selector
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>

static NSArray *kBoolYes = nil;      // 恒返回 YES 的 selector
static NSArray *kNilStr  = nil;      // 恒返回 nil/空字符串的 selector
static NSArray *kFuture  = nil;      // 恒返回很远的未来时间
static NSArray *kBlockNoop = nil;    // 空实现（阻止退出/弹窗）

static BOOL retYES(id s, SEL c){ return YES; }
static id retNil(id s, SEL c){ return nil; }
static double retFuture(id s, SEL c){ return 4102444799.0; } // 2099-12-31
static double retZero(id s, SEL c){ return 0.0; }
static long retLong0(id s, SEL c){ return 0; }
static void void_noop(id s, SEL c){ }

static void sweep(void){
  int n = objc_getClassList(NULL,0);
  Class *cls = (Class *)calloc(n, sizeof(Class));
  n = objc_getClassList(cls,n);
  for(int i=0;i<n;i++){
    Class K = cls[i];
    const char *kn = class_getName(K);
    if(!kn) continue;
    // 只处理本 app 二进制/image 定义的类，避免误伤系统类
    Dl_info di; if(dladdr((__bridge void *)K,&di) && di.dli_fname){
      NSString *path=[NSString stringWithUTF8String:di.dli_fname];
      if(!([path containsString:@"Podcasts.app"]||[path containsString:@"StarbucksSTE"]||[path containsString:@"/var/"]||[path containsString:@"Bundle/Application"])) continue;
    } else continue;
    unsigned mc = 0;
    Method *ms = class_copyMethodList(K,&mc);
    for(unsigned j=0;j<mc;j++){
      SEL sel = method_getName(ms[j]);
      const char *sn = sel_getName(sel);
      if(!sn) continue;
      NSString *s = [NSString stringWithUTF8String:sn];
      for(NSString *pat in kBoolYes){
        if([s isEqualToString:pat] || [s hasPrefix:pat]){
          method_setImplementation(ms[j], (IMP)retYES);
        }
      }
      for(NSString *pat in kNilStr){
        if([s isEqualToString:pat]){
          method_setImplementation(ms[j], (IMP)retNil);
        }
      }
      for(NSString *pat in kFuture){
        if([s isEqualToString:pat] || [s rangeOfString:pat].location!=NSNotFound){
          const char *rt = method_getTypeEncoding(ms[j]);
          if(rt && rt[0]=='d') method_setImplementation(ms[j], (IMP)retFuture);
        }
      }
      for(NSString *pat in kBlockNoop){
        if([s isEqualToString:pat]){
          const char *rt = method_getTypeEncoding(ms[j]);
          if(rt && rt[0]=='v') method_setImplementation(ms[j], (IMP)void_noop);
        }
      }
      // 兜底：任何 hasValid* / *isValid* / *isExpired* 之类布尔
      if(([s hasPrefix:@"hasValid"]||[s hasPrefix:@"isValid"]||[s hasPrefix:@"isVIP"]||
          [s hasPrefix:@"isAuthorized"]||[s hasPrefix:@"isActivated"]) &&
         method_getTypeEncoding(ms[j])[0]=='c'){
        method_setImplementation(ms[j], (IMP)retYES);
      }
      if(([s hasPrefix:@"isExpired"]||[s hasPrefix:@"isInvalid"]||[s hasPrefix:@"isBanned"]) &&
         method_getTypeEncoding(ms[j])[0]=='c'){
        method_setImplementation(ms[j], (IMP)retZero); // 让 isExpired 返回 NO(0)
      }
    }
    free(ms);
  }
  free(cls);
}

__attribute__((constructor))
static void init_bypass(void){
  kBoolYes = @[@"hasValidCoreLease",@"hasSavedCard",@"hasValidFeatureLease",
               @"hasValidSession",@"isAuthorized",@"isActivated",@"isVIP"];
  kNilStr  = @[@"savedCard",@"activeCard",@"messageMeansInvalidSession:",
               @"responseIndicatesSessionInvalid:error:",@"messageIndicatesSessionInvalid:",
               @"_expireTimeFromText:",@"_expireTextFromRaw:fallbackMessage:"];
  kFuture  = @[@"coreLeaseExpiresAt",@"featureLeaseExpiresAt",@"vipExpireTime",@"secureExpiresAt"];
  kBlockNoop = @[@"_showExpiredAlertAndExitWithMessage:",@"stop"];
  sweep();
  NSLog(@"[STE-bypass] sweep applied");
}
