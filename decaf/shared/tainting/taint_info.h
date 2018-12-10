#ifndef __TAINT_INFO_H__
#define __TAINT_INFO_H__

#define SIZE 1000
typedef struct _TaintInfoItem
{
   uint32_t mMiddleIndex;
   uint32_t mLeafIndex;
   uint32_t mBitmapIndex;
}TaintInfoItem_t;

typedef struct _TaintInfo
{
    TaintInfoItem_t mTaintInfo[SIZE];
    uint32_t mLen;
}TaintInfo_t;

void get_taint_info();

#endif  /* __TAINT_INFO_H__ */
