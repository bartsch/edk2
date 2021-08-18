/** @file

  Virtio Pmem Device specific type and macro definitions corresponding to the
  virtio-x.y.z specification.

  Copyright (C) 2021, Daniel Martin <consume.noise@gmail.com>
  Copyright (C) 2012, Red Hat, Inc.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef INDUSTRYSTANDARD_VIRTIO_PMEM_H
#define INDUSTRYSTANDARD_VIRTIO_PMEM_H

#include <IndustryStandard/Virtio.h>


//
// virtio-x.y.z, Appendix D: Block Device
//
typedef struct {
  UINT64 Start;
  UINT64 Size;
} VIRTIO_PMEM_CONFIG;

#define OFFSET_OF_VPMEM(Field) OFFSET_OF (VIRTIO_PMEM_CONFIG, Field)
#define SIZE_OF_VPMEM(Field)   (sizeof ((VIRTIO_PMEM_CONFIG *) 0)->Field)

#define VIRTIO_PMEM_REQ_TYPE_FLUSH 0

typedef struct {
  UINT32 Type;
} VIRTIO_PMEM_REQ;

typedef struct {
  UINT32 Ret;
} VIRTIO_PMEM_RESP;


#endif // INDUSTRYSTANDARD_VIRTIO_PMEM_H
