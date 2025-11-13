# Check-UEFISecureBootVariables

PowerShell scripts to check the UEFI KEK, DB and DBX Secure Boot variables.

> [!IMPORTANT]
> The DBX checking in this script is made for x64 and arm64 systems. If you are using an x86 or arm system, it is necessary to replace the `*.bin` files with ones for your system architecture and edit their filenames in the PowerShell script (`Check UEFI KEK, DB and DBX.ps1`) accordingly. The `*.bin` files for various architectures can be obtained from [github.com/microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects/tree/main/PostSignedObjects/DBX).

## Checking the KEK, DB and DBX variables

Right-click `Check UEFI KEK, DB and DBX.cmd` and *Run as administrator*.

Example output:

![Screenshot](https://github.com/user-attachments/assets/efa6fcfb-c505-43aa-8c19-c30d10bc6f60)

> [!NOTE]
> This script only checks for known Microsoft certificates in the KEK and DB and will not show any other certificates even if they are present. To view all certificates that are present, see [Viewing all the UEFI Secure Boot variables](#viewing-all-the-uefi-secure-boot-variables) below.

## Re-applying the Secure Boot DBX updates

If the Secure Boot variables were accidentally reset to default in the UEFI/BIOS settings for example, it is possible to make Windows re-apply the DBX updates that Windows had previously applied. Double-click `Apply DBX update (restart required).reg` and add the changes to the registry then restart Windows and wait for awhile. The DBX updates should be applied after that.

> [!NOTE]
> Using the `.reg` file will reset all other changes made to the registry bits. See [Registry bits for applying Secure Boot updates](#registry-bits-for-applying-secure-boot-updates) below.

## Deploying Windows UEFI CA 2023 certificate to Secure Boot Allowed Signature Database (DB)

Windows February 13, 2024 cumulative update includes the ability to apply the Windows UEFI CA 2023 certificate to UEFI Secure Boot Allowed Signature Database (DB). To do so, double-click `Apply DB update (restart required).reg` and add the changes to the registry then restart Windows and wait for awhile. The DB updates should be applied after that. For more information, refer to [KB5036210](https://support.microsoft.com/en-gb/topic/kb5036210-deploying-windows-uefi-ca-2023-certificate-to-secure-boot-allowed-signature-database-db-a68a3eae-292b-4224-9490-299e303b450b) and [Evolving the Secure Boot Ecosystem](https://uefi.org/sites/default/files/resources/Evolving%20the%20Secure%20Boot%20Ecosystem_Flick%20and%20Sutherland.pdf).

> [!NOTE]
> Using the `.reg` file will reset all other changes made to the registry bits. See [Registry bits for applying Secure Boot updates](#registry-bits-for-applying-secure-boot-updates) below.

## Registry bits for applying Secure Boot updates

The bits in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates` DWORD control what updates are to be applied by Windows. The updates are applied usually upon restart or with `Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"` which also automatically runs every 12 hours.

The following are the possible bit values that are currently known.

| Bit | Usage |
| - | - |
| 0x0002 | Apply DBX updates. |
| 0x0004 | Apply the Microsoft Corporation KEK 2K CA 2023 to the KEK. |
| 0x0040 | Apply the Windows UEFI CA 2023 to the DB. |
| 0x0080 | Apply the Windows Production PCA 2011 to the DBX. |
| 0x0100 | Apply the boot manager, signed by the Windows UEFI CA 2023, to the boot partition. |
| 0x0200 | Apply Secure Version Number (SVN) update to the firmware. |
| 0x0800 | Apply the Microsoft Option ROM UEFI CA 2023 to the DB. |
| 0x1000 | Apply the Microsoft UEFI CA 2023 to the DB. |
| 0x4000 | This bit modifies the behavior of the 0x0800 and 0x1000 bits to only apply the Microsoft UEFI CA 2023 and Microsoft Option ROM UEFI CA 2023 if the DB already has the Microsoft Corporation UEFI CA 2011. |

> [!IMPORTANT]
> Please carefully read and understand [How to manage the Windows Boot Manager revocations for Secure Boot changes associated with CVE-2023-24932](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d), [Secure Boot Certificate updates: Guidance for IT professionals and organizations](https://support.microsoft.com/en-us/topic/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations-e2b43f9f-b424-42df-bc6a-8476db65ab2f) as well as [Registry key updates for Secure Boot: Windows devices with IT-managed updates](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d) before attempting to manually modify the registry to apply updates. It is also recommended to read the other resources listed above these in the references section.

## Viewing Secure Boot DB and DBX variable update events

Double-click `Show Secure Boot update events.cmd` to display all the Secure Boot DB and DBX variable update events. Refer to [KB5016061](https://support.microsoft.com/en-gb/topic/kb5016061-secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69) for details on interpreting the events.

## Viewing all the UEFI Secure Boot variables

To display all the UEFI Secure Boot variables in readable format, right-click `Show UEFI PK, KEK, DB and DBX.cmd` and *Run as administrator*. All certificates in the PK, KEK and DB variables as well as all hashes in the DBX variable will be displayed.

## References

- [Windows Secure Boot Key Creation and Management Guidance](https://learn.microsoft.com/en-my/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11)
- [Get-SecureBootUEFI](https://learn.microsoft.com/en-my/powershell/module/secureboot/get-securebootuefi?view=windowsserver2022-ps)
- [Microsoft guidance for applying Secure Boot DBX update (KB4575994)](https://support.microsoft.com/en-gb/topic/microsoft-guidance-for-applying-secure-boot-dbx-update-kb4575994-e3b9e4cb-a330-b3ba-a602-15083965d9ca)
- [KB5016061: Secure Boot DB and DBX variable update events](https://support.microsoft.com/en-gb/topic/kb5016061-secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69)
- [KB5036210: Deploying Windows UEFI CA 2023 certificate to Secure Boot Allowed Signature Database (DB)](https://support.microsoft.com/en-gb/topic/kb5036210-deploying-windows-uefi-ca-2023-certificate-to-secure-boot-allowed-signature-database-db-a68a3eae-292b-4224-9490-299e303b450b)
- [How to manage the Windows Boot Manager revocations for Secure Boot changes associated with CVE-2023-24932](https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)
- [Windows Secure Boot certificate expiration and CA updates](https://support.microsoft.com/en-us/topic/windows-secure-boot-certificate-expiration-and-ca-updates-7ff40d33-95dc-4c3c-8725-a9b95457578e)
- [Secure Boot Certificate updates: Guidance for IT professionals and organizations](https://support.microsoft.com/en-us/topic/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations-e2b43f9f-b424-42df-bc6a-8476db65ab2f)
- [Registry key updates for Secure Boot: Windows devices with IT-managed updates](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d)
- [Check-Dbx.ps1](https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0#file-check-dbx-ps1)
- [Get-UEFIDatabaseSignatures.ps1](https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0?permalink_comment_id=4572467#gistcomment-4572467)
- [Only the latest DBX update is needed (1)](https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0?permalink_comment_id=4661159#gistcomment-4661159)
- [Only the latest DBX update is needed (2)](https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0?permalink_comment_id=4661596#gistcomment-4661596)
- [UEFI Revocation List File](https://uefi.org/revocationlistfile)
- [Microsoft - Secure Boot Objects](https://github.com/microsoft/secureboot_objects)
- [Evolving the Secure Boot Ecosystem](https://uefi.org/sites/default/files/resources/Evolving%20the%20Secure%20Boot%20Ecosystem_Flick%20and%20Sutherland.pdf)
- [Update the dbx database to add back the same dbx entries as the cumulative update applied](https://support.hp.com/my-en/document/ish_9642671-9641393-16#GUID-49C8C19D-32CC-4FF9-A635-4A87C0BB0046)
