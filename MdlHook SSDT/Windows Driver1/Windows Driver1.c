#include <ntifs.h>
#include <ntddk.h>

#define Index_NtOpenProcess 190

//声明下即可用
extern UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);;

typedef struct _SYSTEM_SERVICE_TABLE
{
	PULONG ServiceTableBase; //这个指向系统服务函数地址表
	PULONG ServiceCounterTableBase;
	ULONG NumberOfService; //服务函数的个数
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

//Flag为1则代表去HOOK，Flag为0则代表取消HOOK
BOOLEAN MdlTest(BOOLEAN Flag)
{
	PMDL mMdl = NULL;

	ULONG* ServiceTableBase = NULL;

	mMdl = MmCreateMdl(NULL, KeServiceDescriptorTable.ServiceTableBase, 4 * KeServiceDescriptorTable.NumberOfService);
	//根据基址和大小创建mdl

	if (mMdl == NULL)
	{
		KdPrint(("分配mdl失败！\n"));
		return FALSE;
	}

	MmBuildMdlForNonPagedPool(mMdl);
	//在非分页内存池建立mdl

	//网上都说是确定可读可写权限，但是字面上的意思似乎是拷贝到系统空间.....
	mMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

	//锁定Mdl内存页
	ServiceTableBase = (ULONG*)MmMapLockedPages(mMdl, KernelMode);

	if (ServiceTableBase == NULL)
	{
		KdPrint(("锁定页面失败！\n"));
		return FALSE;
	}

	if (Flag)
	{
		old_NtOpenProcess = (NTOPENPROCESS)ServiceTableBase[Index_NtOpenProcess];				//保存原始状态
		ServiceTableBase[Index_NtOpenProcess] = (ULONG)mNtOpenProcess;							//用新的函数替代
	}
	else
	{
		ServiceTableBase[Index_NtOpenProcess] = (ULONG)old_NtOpenProcess;						//恢复
		old_NtOpenProcess = NULL;																//清零
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
	PEPROCESS OpenProcess = NULL;						//将要打开的进程
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &OpenProcess);

	if (!NT_SUCCESS(status) || OpenProcess == NULL)
		return old_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

	ObDereferenceObject(OpenProcess);

	if (strstr(PsGetProcessImageFileName(OpenProcess), "calc"))
	{
		KdPrint(("禁止打开calc！\n"));
		return STATUS_ACCESS_DENIED;
	}

	return old_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}