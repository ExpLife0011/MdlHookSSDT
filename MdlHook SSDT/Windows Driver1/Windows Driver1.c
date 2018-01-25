#include <ntifs.h>
#include <ntddk.h>

#define Index_NtOpenProcess 190

//�����¼�����
extern UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);;

typedef struct _SYSTEM_SERVICE_TABLE
{
	PULONG ServiceTableBase; //���ָ��ϵͳ��������ַ��
	PULONG ServiceCounterTableBase;
	ULONG NumberOfService; //�������ĸ���
	ULONG ParamTableBase;
}SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

__declspec(dllimport) SYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

typedef NTSTATUS(*NTOPENPROCESS)(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);

NTSTATUS mNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	);

NTOPENPROCESS old_NtOpenProcess;

//FlagΪ1�����ȥHOOK��FlagΪ0�����ȡ��HOOK
BOOLEAN MdlTest(BOOLEAN Flag)
{
	PMDL mMdl = NULL;

	ULONG* ServiceTableBase = NULL;

	mMdl = MmCreateMdl(NULL, KeServiceDescriptorTable.ServiceTableBase, 4 * KeServiceDescriptorTable.NumberOfService);
	//���ݻ�ַ�ʹ�С����mdl

	if (mMdl == NULL)
	{
		KdPrint(("����mdlʧ�ܣ�\n"));
		return FALSE;
	}

	MmBuildMdlForNonPagedPool(mMdl);
	//�ڷǷ�ҳ�ڴ�ؽ���mdl

	//���϶�˵��ȷ���ɶ���дȨ�ޣ����������ϵ���˼�ƺ��ǿ�����ϵͳ�ռ�.....
	mMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

	//����Mdl�ڴ�ҳ
	ServiceTableBase = (ULONG*)MmMapLockedPages(mMdl, KernelMode);

	if (ServiceTableBase == NULL)
	{
		KdPrint(("����ҳ��ʧ�ܣ�\n"));
		return FALSE;
	}

	if (Flag)
	{
		old_NtOpenProcess = (NTOPENPROCESS)ServiceTableBase[Index_NtOpenProcess];				//����ԭʼ״̬
		ServiceTableBase[Index_NtOpenProcess] = (ULONG)mNtOpenProcess;							//���µĺ������
	}
	else
	{
		ServiceTableBase[Index_NtOpenProcess] = (ULONG)old_NtOpenProcess;						//�ָ�
		old_NtOpenProcess = NULL;																//����
	}

	IoFreeMdl(mMdl);

	return TRUE;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	MdlTest(0);
	KdPrint(("Unload Success!\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	MdlTest(1);
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}

NTSTATUS mNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	)
{
	PEPROCESS OpenProcess = NULL;						//��Ҫ�򿪵Ľ���
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &OpenProcess);

	if (!NT_SUCCESS(status) || OpenProcess == NULL)
		return old_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

	ObDereferenceObject(OpenProcess);

	if (strstr(PsGetProcessImageFileName(OpenProcess), "calc"))
	{
		KdPrint(("��ֹ��calc��\n"));
		return STATUS_ACCESS_DENIED;
	}

	return old_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}