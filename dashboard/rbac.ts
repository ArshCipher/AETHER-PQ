// Role-Based Access Control Permissions Definitions

export type Permission =
  | "ViewTelemetry"
  | "ViewLogs"
  | "ExportLogs"
  | "OperatorOverride"
  | "ManualPolicyControl"
  | "RunBenchmarks"
  | "IssueCertificates"
  | "RevokeCertificates"
  | "ModifyConfiguration"
  | "RestartServices"
  | "ManageUsers"
  | "ManageCertificates"
  | "ManageSimulation"
  | "ManageHardwareDeployment"
  | "QueryUAV"
  | "ListUAVFiles"
  | "RetrieveUAVFiles";

export type Role = "Admin" | "Operator" | "Researcher" | "Viewer";

// Map Roles to Permissions Lists
const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  Admin: [
    "ViewTelemetry",
    "ViewLogs",
    "ExportLogs",
    "OperatorOverride",
    "ManualPolicyControl",
    "RunBenchmarks",
    "IssueCertificates",
    "RevokeCertificates",
    "ModifyConfiguration",
    "RestartServices",
    "ManageUsers",
    "ManageCertificates",
    "ManageSimulation",
    "ManageHardwareDeployment",
    "QueryUAV",
    "ListUAVFiles",
    "RetrieveUAVFiles"
  ],
  Operator: [
    "ViewTelemetry",
    "ViewLogs",
    "ExportLogs",
    "OperatorOverride",
    "ManualPolicyControl",
    "IssueCertificates",
    "RevokeCertificates",
    "RestartServices",
    "ManageCertificates",
    "ManageSimulation",
    "QueryUAV",
    "ListUAVFiles",
    "RetrieveUAVFiles"
  ],
  Researcher: [
    "ViewTelemetry",
    "ViewLogs",
    "ExportLogs",
    "RunBenchmarks",
    "QueryUAV",
    "ListUAVFiles"
  ],
  Viewer: [
    "ViewTelemetry",
    "ViewLogs"
  ]
};

// Check if a role possesses a specific permission
export function hasPermission(role: string, permission: Permission): boolean {
  const perms = ROLE_PERMISSIONS[role as Role];
  if (!perms) return false;
  return perms.includes(permission);
}
