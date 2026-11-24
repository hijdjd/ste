#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>

static BOOL retYES(id s,SEL c){return YES;}
static BOOL retNO(id s,SEL c){return NO;}
static double retFuture(id s,SEL c){return 4102444799.0;}
static void noop(id s,SEL c){}

// 精确白名单：只改这些名字，其它一概不动
static const char* gFail[]={"responseMessageIndicatesLoginFailure:","responseIndicatesSessionInvalid:error:",
  "messageMeansInvalidSession:","messageIndicatesSessionInvalid:",0};
static const char* gYes[]={"hasValidCoreLease","hasSavedCard","hasValidFeatureLease","hasValidSession",0};
static const char* gTime[]={"coreLeaseExpiresAt","featureLeaseExpiresAt","vipExpireTime","secureExpiresAt",0};
static const char* gExit[]={"_showExpiredAlertAndExitWithMessage:",0};

static BOOL inList(const char**arr,const char*sn){for(int i=0;arr[i];i++)if(!strcmp(arr[i],sn))return YES;return NO;}

static void sweep(void){
  NSMutableString*dump=[NSMutableString string];
  int dn=objc_getClassList(NULL,0);
  Class*dcl=(Class*)calloc(dn,sizeof(Class)); dn=objc_getClassList(dcl,dn);
  for(int k=0;k<dn;k++){
    const char*cn=class_getName(dcl[k]);
    if(!cn) continue;
    unsigned m2=0; Method*mm=class_copyMethodList(dcl[k],&m2);
    for(unsigned q=0;q<m2;q++){
      const char*sn2=sel_getName(method_getName(mm[q]));
      NSString*S=[NSString stringWithUTF8String:sn2];
      if([S containsString:@"Login"]||[S containsString:@"Card"]||[S containsString:@"Lease"]||[S containsString:@"Token"]||
         [S containsString:@"Vip"]||[S containsString:@"vip"]||[S containsString:@"Expire"]||[S containsString:@"expire"]||
         [S containsString:@"Valid"]||[S containsString:@"Auth"]||[S containsString:@"Session"]||[S containsString:@"Ticket"]||
         [S containsString:@"Gate"]||[S containsString:@"Verify"]||[S containsString:@"verify"]||[S containsString:@"Entitl"]||
         [S containsString:@"Grant"]||[S containsString:@"Premium"]||[S containsString:@"Purchase"]){
        [dump appendFormat:@"%s::%s::%s\n",cn,sn2,method_getTypeEncoding(mm[q])];
      }
    }
    free(mm);
  }
  free(dcl);
  // 多路输出，确保能拿到
  [dump writeToFile:@"/var/mobile/stehook_dump.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
  NSString *doc = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask,YES) firstObject];
  if(doc) [dump writeToFile:[doc stringByAppendingPathComponent:@"stehook_dump.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
  [dump writeToFile:@"/tmp/stehook_dump.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
  // 塞进系统剪贴板（最可靠，用户无需找文件）
  if(dump.length < 100000){
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(8*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
      UIPasteboard *pb = [UIPasteboard generalPasteboard];
      pb.string = [NSString stringWithFormat:@"STEHOOKDUMP_START\n%@\nSTEHOOKDUMP_END",dump];
      NSLog(@"[STE] dump -> clipboard %lu chars",(unsigned long)dump.length);
    });
  }
  int n=objc_getClassList(NULL,0);
  Class*cls=(Class*)calloc(n,sizeof(Class)); n=objc_getClassList(cls,n);
  for(int i=0;i<n;i++){
    unsigned mc=0; Method*ms=class_copyMethodList(cls[i],&mc);
    for(unsigned j=0;j<mc;j++){
      SEL sel=method_getName(ms[j]); const char*sn=sel_getName(sel);
      const char*te=method_getTypeEncoding(ms[j]);
      if(inList(gFail,sn)&&(te[0]=='c'||te[0]=='B')) method_setImplementation(ms[j],(IMP)retNO);
      else if(inList(gYes,sn)&&(te[0]=='c'||te[0]=='B')) method_setImplementation(ms[j],(IMP)retYES);
      else if(inList(gTime,sn)&&te[0]=='d') method_setImplementation(ms[j],(IMP)retFuture);
      else if(inList(gExit,sn)&&te[0]=='v') method_setImplementation(ms[j],(IMP)noop);
    }
    free(ms);
  }
  free(cls);
  NSLog(@"[STE] precise sweep done");
}

__attribute__((constructor)) static void ste_init(void){ sweep(); }
