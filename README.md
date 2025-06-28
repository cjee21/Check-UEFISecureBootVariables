# Check-UEFISecureBootVariables

PowerShell scripts to check the UEFI KEK, DB and DBX Secure Boot variables.

> [!IMPORTANT]
> The DBX checking in this script is made for x64 and arm64 systems. If you are using an x86 or arm system, it is necessary to replace the `*.bin` files with ones for your system architecture and edit their filenames in the PowerShell script (`Check UEFI KEK, DB and DBX.ps1`) accordingly. The `*.bin` files for various architectures can be obtained from [github.com/microsoft/secureboot_objects](https://github.com/microsoft/secureboot_objects/tree/main/PostSignedObjects/DBX).

## Checking the KEK, DB and DBX variables

Right-click `Check UEFI KEK, DB and DBX.cmd` and *Run as administrator*.

Example output:

![Screenshot](https://github.com/user-attachments/assets/9035677f-faea-4a73-8f3c-fd462544841a)

> [!NOTE]
> This script only checks for known Microsoft certificates in the KEK and DB and will not show any other certificates even if they are present. To view all certificates that are present, see [Viewing all the UEFI Secure Boot variables](#viewing-all-the-uefi-secure-boot-variables) below.

## Re-applying the Secure Boot DBX updates

If the Secure Boot variables were accidentally reset to default in the UEFI/BIOS settings for example, it is possible to make Windows re-apply the DBX updates that Windows had previously applied. Double-click `Apply DBX update (restart required).reg` and add the changes to the registry then restart Windows and wait for awhile. The DBX updates should be applied after that.

## Deploying Windows UEFI CA 2023 certificate to Secure Boot Allowed Signature Database (DB)

Windows February 13, 2024 cumulative update includes the ability to apply the Windows UEFI CA 2023 certificate to UEFI Secure Boot Allowed Signature Database (DB). To do so, double-click `Apply DB update (restart required).reg` and add the changes to the registry then restart Windows and wait for awhile. The DB updates should be applied after that. For more information, refer to [KB5036210](https://support.microsoft.com/en-gb/topic/kb5036210-deploying-windows-uefi-ca-2023-certificate-to-secure-boot-allowed-signature-database-db-a68a3eae-292b-4224-9490-299e303b450b) and [Evolving the Secure Boot Ecosystem](https://uefi.org/sites/default/files/resources/Evolving%20the%20Secure%20Boot%20Ecosystem_Flick%20and%20Sutherland.pdf).

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
- [Check-Dbx.ps1](https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0#file-check-dbx-ps1)
- [Get-UEFIDatabaseSignatures.ps1](https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0?permalink_comment_id=4572467#gistcomment-4572467)
- [Only the latest DBX update is needed (1)](https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0?permalink_comment_id=4661159#gistcomment-4661159)
- [Only the latest DBX update is needed (2)](https://gist.github.com/out0xb2/f8e0bae94214889a89ac67fceb37f8c0?permalink_comment_id=4661596#gistcomment-4661596)
- [UEFI Revocation List File](https://uefi.org/revocationlistfile)
- [Microsoft - Secure Boot Objects](https://github.com/microsoft/secureboot_objects)
- [Evolving the Secure Boot Ecosystem](https://uefi.org/sites/default/files/resources/Evolving%20the%20Secure%20Boot%20Ecosystem_Flick%20and%20Sutherland.pdf)
- [Update the dbx database to add back the same dbx entries as the cumulative update applied](https://support.hp.com/my-en/document/ish_9642671-9641393-16#GUID-49C8C19D-32CC-4FF9-A635-4A87C0BB0046)
