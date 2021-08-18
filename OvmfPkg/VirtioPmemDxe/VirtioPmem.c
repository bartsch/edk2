/** @file

  This driver produces RamDisk Protocol instances for virtio-pmem devices.

  Copyright (C) 2021, Daniel Martin <consume.noise@gmail.com>
  Copyright (C) 2012, Red Hat, Inc.
  Copyright (c) 2012 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2017, AMD Inc, All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <IndustryStandard/VirtioPmem.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/VirtioLib.h>
#include <Protocol/RamDisk.h>

#define VPMEM_SIG SIGNATURE_64 ('V', 'P', 'M', 'E', 'M', 0, 0, 0)

typedef struct {
  UINT64                   Signature;
  VIRTIO_DEVICE_PROTOCOL   *VirtIo;
  EFI_RAM_DISK_PROTOCOL    *RamDisk;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
} VPMEM_DEV;

#define VPMEM_DEV_FROM_RAM_DISK(RamDiskPointer) \
        CR (RamDiskPointer, VPMEM_DEV, RamDisk, VPMEM_SIG)

/**

  Convenience macro to read region 0 IO space elements of the
  virtio-pmem device, for configuration purposes.

  The following macros make it possible to specify only the "core parameters"
  for such accesses and to derive the rest. By the time VIRTIO_CFG_WRITE()
  returns, the transaction will have been completed.

  @param[in] Dev       Pointer to the VPMEM_DEV structure whose VirtIo space
                       we're accessing. Dev->VirtIo must be valid.

  @param[in] Field     A field name from VPMEM_HDR, identifying the virtio-pmem
                       configuration item to access.

  @param[out] Pointer  (VIRTIO_CFG_READ() only.) The object to receive the
                       value read from the configuration item. Its type must be
                       one of UINT8, UINT16, UINT32, UINT64.

  @return  Status code returned by Virtio->WriteDevice() /
           Virtio->ReadDevice().

**/

#define VIRTIO_CFG_READ(Dev, Field, Pointer) (           \
    (Dev)->VirtIo->ReadDevice (                          \
        (Dev)->VirtIo,                                   \
        OFFSET_OF_VPMEM (Field), SIZE_OF_VPMEM (Field),  \
        sizeof (*(Pointer)), (Pointer)))


/**

  Set up all RamDisk and virtio-pmem aspects of this driver for the specified
  device.

  @param[in out] Dev  The driver instance to configure. The caller is
                      responsible for Dev->VirtIo's validity (ie. working IO
                      access to the underlying virtio-pmem device).

  @retval EFI_SUCCESS      Setup complete.

  @retval EFI_UNSUPPORTED  The driver is unable to work with the
                           virtio-pmem attributes the host provides.

  @return                  Error codes from VIRTIO_CFG_READ().

**/

STATIC
EFI_STATUS
EFIAPI
VirtioPmemInit (
  IN EFI_HANDLE    DeviceHandle,
  IN OUT VPMEM_DEV *Dev
  )
{
  EFI_STATUS Status;
  UINT8      NextDevStat;
  UINT64     Start;
  UINT64     Size;

  //
  // Execute virtio-0.9.5, 2.2.1 Device Initialization Sequence.
  //
  NextDevStat = 0;             // step 1 -- reset device
  Status = Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, NextDevStat);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  NextDevStat |= VSTAT_ACK;    // step 2 -- acknowledge device presence
  Status = Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, NextDevStat);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  NextDevStat |= VSTAT_DRIVER; // step 3 -- we know how to drive it
  Status = Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, NextDevStat);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  //
  // Set Page Size - MMIO VirtIo Specific
  //
  Status = Dev->VirtIo->SetPageSize (Dev->VirtIo, EFI_PAGE_SIZE);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  //
  // step 4a -- retrieve and validate configuration
  //
  Status = VIRTIO_CFG_READ (Dev, Start, &Start);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  Status = VIRTIO_CFG_READ (Dev, Size, &Size);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  if (Start == 0 || Size == 0) {
    Status = EFI_UNSUPPORTED;
    goto Failed;
  }

  Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, 0);

  Status = Dev->RamDisk->Register(Start, Size,
		  &gEfiVirtualDiskGuid, NULL, &Dev->DevicePath);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;

Failed:
    //
    // Notify the host about our failure to setup: virtio-0.9.5, 2.2.2.1 Device
    // Status. VirtIo access failure here should not mask the original error.
    //
    NextDevStat |= VSTAT_FAILED;
    Dev->VirtIo->SetDeviceStatus (Dev->VirtIo, NextDevStat);

    return Status;
}


STATIC
VOID
EFIAPI
VirtioPmemUninit (
  IN EFI_DRIVER_BINDING_PROTOCOL *This,
  IN EFI_HANDLE    DeviceHandle,
  IN OUT VPMEM_DEV *Dev
  )
{
  if (Dev->DevicePath) {
    Dev->RamDisk->Unregister (Dev->DevicePath);
  }

  if (Dev->RamDisk) {
    gBS->UninstallProtocolInterface (DeviceHandle,
            &gEfiRamDiskProtocolGuid, &Dev->RamDisk);
  }

  if (Dev->VirtIo) {
    gBS->CloseProtocol (DeviceHandle, &gVirtioDeviceProtocolGuid,
            This->DriverBindingHandle, DeviceHandle);
  }

  FreePool (Dev);
}


/**

  Device probe function for this driver.

  The DXE core calls this function for any given device in order to see if the
  driver can drive the device.

  Specs relevant in the general sense:

  - UEFI Spec 2.3.1 + Errata C:
    - 6.3 Protocol Handler Services -- for accessing the underlying device
    - 10.1 EFI Driver Binding Protocol -- for exporting ourselves

  - Driver Writer's Guide for UEFI 2.3.1 v1.01:
    - 5.1.3.4 OpenProtocol() and CloseProtocol() -- for accessing the
      underlying device
    - 9 Driver Binding Protocol -- for exporting ourselves

  @param[in]  This                The EFI_DRIVER_BINDING_PROTOCOL object
                                  incorporating this driver (independently of
                                  any device).

  @param[in] DeviceHandle         The device to probe.

  @param[in] RemainingDevicePath  Relevant only for bus drivers, ignored.


  @retval EFI_SUCCESS      The driver supports the device being probed.

  @retval EFI_UNSUPPORTED  Based on virtio-pmem discovery, we do not support
                           the device.

  @return                  Error codes from the OpenProtocol() boot service or
                           the VirtIo protocol.

**/

EFI_STATUS
EFIAPI
VirtioPmemDriverBindingSupported (
  IN EFI_DRIVER_BINDING_PROTOCOL *This,
  IN EFI_HANDLE                  DeviceHandle,
  IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath
  )
{
  EFI_STATUS Status;
  VPMEM_DEV  Dev;

  //
  // Attempt to open the device with the VirtIo set of interfaces. On success,
  // the protocol is "instantiated" for the VirtIo device. Covers duplicate
  // open attempts (EFI_ALREADY_STARTED).
  //
  Status = gBS->OpenProtocol (
                  DeviceHandle,               // candidate device
                  &gVirtioDeviceProtocolGuid, // for generic VirtIo access
                  (VOID **)&Dev.VirtIo,      // handle to instantiate
                  This->DriverBindingHandle,  // requestor driver identity
                  DeviceHandle,               // ControllerHandle, according to
                                              // the UEFI Driver Model
                  EFI_OPEN_PROTOCOL_BY_DRIVER // get exclusive VirtIo access to
                                              // the device; to be released
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Dev.VirtIo->SubSystemDeviceId != VIRTIO_SUBSYSTEM_PMEM) {
    Status = EFI_UNSUPPORTED;
  }

  //
  // We needed VirtIo access only transitorily, to see whether we support the
  // device or not.
  //
  gBS->CloseProtocol (DeviceHandle, &gVirtioDeviceProtocolGuid,
         This->DriverBindingHandle, DeviceHandle);

  return Status;
}


/**

  After we've pronounced support for a specific device in
  DriverBindingSupported(), we start managing said device (passed in by the
  Driver Execution Environment) with the following service.

  See DriverBindingSupported() for specification references.

  @param[in]  This                The EFI_DRIVER_BINDING_PROTOCOL object
                                  incorporating this driver (independently of
                                  any device).

  @param[in] DeviceHandle         The supported device to drive.

  @param[in] RemainingDevicePath  Relevant only for bus drivers, ignored.


  @retval EFI_SUCCESS           Driver instance has been created and
                                initialized  for the virtio-pmem device, it
                                is now accessible via EFI_BLOCK_IO_PROTOCOL.

  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.

  @return                       Error codes from the OpenProtocol() boot
                                service, the VirtIo protocol, VirtioPmemInit(),
                                or the InstallProtocolInterface() boot service.

**/

EFI_STATUS
EFIAPI
VirtioPmemDriverBindingStart (
  IN EFI_DRIVER_BINDING_PROTOCOL *This,
  IN EFI_HANDLE                  DeviceHandle,
  IN EFI_DEVICE_PATH_PROTOCOL    *RemainingDevicePath
  )
{
  VPMEM_DEV  *Dev;
  EFI_STATUS Status;

  Dev = (VPMEM_DEV *) AllocateZeroPool (sizeof (*Dev));
  if (Dev == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Dev->Signature = VPMEM_SIG;

  Status = gBS->OpenProtocol (DeviceHandle, &gVirtioDeviceProtocolGuid,
                  (VOID **)&Dev->VirtIo, This->DriverBindingHandle,
                  DeviceHandle, EFI_OPEN_PROTOCOL_BY_DRIVER);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  Status = gBS->LocateProtocol (&gEfiRamDiskProtocolGuid, NULL,
                  (VOID **)&Dev->RamDisk);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  //
  // VirtIo access granted, configure virtio-pmem device.
  //
  Status = VirtioPmemInit (DeviceHandle, Dev);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  return EFI_SUCCESS;

Failed:
  VirtioPmemUninit (This, DeviceHandle, Dev);

  return Status;
}


/**

  Stop driving a virtio-pmem device and remove its RAM Disk interface.

  This function replays the success path of DriverBindingStart() in reverse.
  The host side virtio-pmem device is reset, so that the OS boot loader or the
  OS may reinitialize it.

  @param[in] This               The EFI_DRIVER_BINDING_PROTOCOL object
                                incorporating this driver (independently of any
                                device).

  @param[in] DeviceHandle       Stop driving this device.

  @param[in] NumberOfChildren   Since this function belongs to a device driver
                                only (as opposed to a bus driver), the caller
                                environment sets NumberOfChildren to zero, and
                                we ignore it.

  @param[in] ChildHandleBuffer  Ignored (corresponding to NumberOfChildren).

**/

EFI_STATUS
EFIAPI
VirtioPmemDriverBindingStop (
  IN EFI_DRIVER_BINDING_PROTOCOL *This,
  IN EFI_HANDLE                  DeviceHandle,
  IN UINTN                       NumberOfChildren,
  IN EFI_HANDLE                  *ChildHandleBuffer
  )
{
  EFI_STATUS            Status;
  VPMEM_DEV             *Dev;
  EFI_RAM_DISK_PROTOCOL *RamDisk;

  Status = gBS->OpenProtocol (
                  DeviceHandle,                  // candidate device
                  &gEfiRamDiskProtocolGuid,    // retrieve the RAM Disk iface
                  (VOID **)&RamDisk,                 // target pointer
                  This->DriverBindingHandle,     // requestor driver identity
                  DeviceHandle,                  // requesting lookup for dev.
                  EFI_OPEN_PROTOCOL_GET_PROTOCOL // lookup only, no ref. added
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Dev = VPMEM_DEV_FROM_RAM_DISK (RamDisk);

  VirtioPmemUninit (This, DeviceHandle, Dev);

  return EFI_SUCCESS;
}


//
// The static object that groups the Supported() (ie. probe), Start() and
// Stop() functions of the driver together. Refer to UEFI Spec 2.3.1 + Errata
// C, 10.1 EFI Driver Binding Protocol.
//
STATIC EFI_DRIVER_BINDING_PROTOCOL gDriverBinding = {
  &VirtioPmemDriverBindingSupported,
  &VirtioPmemDriverBindingStart,
  &VirtioPmemDriverBindingStop,
  0x10, // Version, must be in [0x10 .. 0xFFFFFFEF] for IHV-developed drivers
  NULL, // ImageHandle, to be overwritten by
        // EfiLibInstallDriverBindingComponentName2() in VirtioPmemEntryPoint()
  NULL  // DriverBindingHandle, ditto
};


//
// The purpose of the following scaffolding (EFI_COMPONENT_NAME_PROTOCOL and
// EFI_COMPONENT_NAME2_PROTOCOL implementation) is to format the driver's name
// in English, for display on standard console devices. This is recommended for
// UEFI drivers that follow the UEFI Driver Model. Refer to the Driver Writer's
// Guide for UEFI 2.3.1 v1.01, 11 UEFI Driver and Controller Names.
//
// Device type names ("Virtio PMem Device") are not formatted because the
// driver supports only that device type. Therefore the driver name suffices
// for unambiguous identification.
//

STATIC
EFI_UNICODE_STRING_TABLE mDriverNameTable[] = {
  { "eng;en", L"Virtio PMem Driver" },
  { NULL,     NULL                   }
};

STATIC
EFI_COMPONENT_NAME_PROTOCOL gComponentName;

EFI_STATUS
EFIAPI
VirtioPmemGetDriverName (
  IN  EFI_COMPONENT_NAME_PROTOCOL *This,
  IN  CHAR8                       *Language,
  OUT CHAR16                      **DriverName
  )
{
  return LookupUnicodeString2 (
           Language,
           This->SupportedLanguages,
           mDriverNameTable,
           DriverName,
           (BOOLEAN)(This == &gComponentName) // Iso639Language
           );
}

EFI_STATUS
EFIAPI
VirtioPmemGetDeviceName (
  IN  EFI_COMPONENT_NAME_PROTOCOL *This,
  IN  EFI_HANDLE                  DeviceHandle,
  IN  EFI_HANDLE                  ChildHandle,
  IN  CHAR8                       *Language,
  OUT CHAR16                      **ControllerName
  )
{
  return EFI_UNSUPPORTED;
}

STATIC
EFI_COMPONENT_NAME_PROTOCOL gComponentName = {
  &VirtioPmemGetDriverName,
  &VirtioPmemGetDeviceName,
  "eng" // SupportedLanguages, ISO 639-2 language codes
};

STATIC
EFI_COMPONENT_NAME2_PROTOCOL gComponentName2 = {
  (EFI_COMPONENT_NAME2_GET_DRIVER_NAME)     &VirtioPmemGetDriverName,
  (EFI_COMPONENT_NAME2_GET_CONTROLLER_NAME) &VirtioPmemGetDeviceName,
  "en" // SupportedLanguages, RFC 4646 language codes
};


//
// Entry point of this driver.
//
EFI_STATUS
EFIAPI
VirtioPmemEntryPoint (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  return EfiLibInstallDriverBindingComponentName2 (
           ImageHandle,
           SystemTable,
           &gDriverBinding,
           ImageHandle,
           &gComponentName,
           &gComponentName2
           );
}

