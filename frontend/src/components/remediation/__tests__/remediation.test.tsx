import {
  render,
  screen,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import RemediationList from "../RemediationList";
import RemediationDetail from "../RemediationDetail";
import ExecutePanel from "../ExecutePanel";
import RollbackPanel from "../RollbackPanel";
import AuditTrail from "../AuditTrail";
import AutoConfigPanel from "../AutoConfigPanel";

const mockExecuteMutate = vi.fn();
const mockRollbackMutate = vi.fn();
const mockSaveConfigMutate = vi.fn();

let mockExecuteState = {
  mutate: mockExecuteMutate,
  isPending: false,
  isSuccess: false,
  isError: false,
  data: null as unknown,
  error: null as unknown,
};

let mockRollbackState = {
  mutate: mockRollbackMutate,
  isPending: false,
  isSuccess: false,
  isError: false,
  data: null as unknown,
  error: null as unknown,
};

let mockAuditState = {
  data: {
    entries: [
      {
        action_id: "act-1",
        check_id: "CHECK_01",
        tier: "tier_2_oneclick",
        status: "success",
        initiated_by: "alice",
        created_at: "2026-01-01T00:00:00Z",
      },
    ],
  } as unknown,
  isLoading: false,
  error: null as unknown,
};

let mockConfigState = {
  data: {
    configs: [
      {
        account_id: "123",
        check_id: "CHECK_04",
        enabled: true,
        rollback_window_minutes: 30,
        notify_on_action: true,
        approved_by: "admin",
      },
    ],
  } as unknown,
  isLoading: false,
  error: null as unknown,
};

vi.mock("@/hooks", () => ({
  useExecuteRemediation: () => mockExecuteState,
  useRollbackRemediation: () => mockRollbackState,
  useAuditTrail: () => mockAuditState,
  useRemediationConfigs: () => mockConfigState,
  useSaveConfig: () => ({
    mutate: mockSaveConfigMutate,
    isPending: false,
  }),
}));

function Wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });
  return (
    <QueryClientProvider client={qc}>
      {children}
    </QueryClientProvider>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockExecuteState = {
    mutate: mockExecuteMutate,
    isPending: false,
    isSuccess: false,
    isError: false,
    data: null,
    error: null,
  };
  mockRollbackState = {
    mutate: mockRollbackMutate,
    isPending: false,
    isSuccess: false,
    isError: false,
    data: null,
    error: null,
  };
  mockAuditState = {
    data: {
      entries: [
        {
          action_id: "act-1",
          check_id: "CHECK_01",
          tier: "tier_2_oneclick",
          status: "success",
          initiated_by: "alice",
          created_at: "2026-01-01T00:00:00Z",
        },
      ],
    },
    isLoading: false,
    error: null,
  };
  mockConfigState = {
    data: {
      configs: [
        {
          account_id: "123",
          check_id: "CHECK_04",
          enabled: true,
          rollback_window_minutes: 30,
          notify_on_action: true,
          approved_by: "admin",
        },
      ],
    },
    isLoading: false,
    error: null,
  };
});

const mockItems = [
  {
    remediation_id: "REM_01",
    check_id: "CHECK_01",
    title: "Block S3 Public Access",
    severity: "critical",
    domain: "data_protection",
    estimated_fix_time_minutes: 5,
    tier: 2,
    console_steps: ["Go to S3", "Click Block"],
    cli_command: "aws s3api ...",
    cli_example: "aws s3api put-public-access-block",
    terraform_snippet: 'resource "aws_s3" {}',
    risk_reduction: "High",
    rollback_difficulty: "Easy",
    references: [
      {
        framework: "CIS AWS",
        control_id: "2.1.1",
        title: "S3 Block",
      },
    ],
  },
];

describe("RemediationList", () => {
  it("renders items", () => {
    render(
      <RemediationList
        items={mockItems}
        selectedId={null}
        onSelect={() => {}}
      />,
    );
    expect(
      screen.getByText("Block S3 Public Access"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Root Account MFA Not Enabled",
      ),
    ).toBeInTheDocument();
  });

  it("renders empty state", () => {
    render(
      <RemediationList
        items={[]}
        selectedId={null}
        onSelect={() => {}}
      />,
    );
    expect(
      screen.getByText(
        /no remediation suggestions/i,
      ),
    ).toBeInTheDocument();
  });

  it("calls onSelect on click", async () => {
    const onSelect = vi.fn();
    const user = userEvent.setup();
    render(
      <RemediationList
        items={mockItems}
        selectedId={null}
        onSelect={onSelect}
      />,
    );

    await user.click(
      screen.getByText("Block S3 Public Access"),
    );
    expect(onSelect).toHaveBeenCalledWith("REM_01");
  });

  it("highlights selected item", () => {
    const { container } = render(
      <RemediationList
        items={mockItems}
        selectedId="REM_01"
        onSelect={() => {}}
      />,
    );
    const btn = container.querySelector("button")!;
    expect(btn.className).toContain(
      "border-primary-500",
    );
  });
});

describe("RemediationDetail", () => {
  it("renders title and metadata", () => {
    render(
      <RemediationDetail item={mockItems[0]} />,
    );
    expect(
      screen.getByText("Block S3 Public Access"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/REM_01/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Fix time: ~5m/),
    ).toBeInTheDocument();
  });

  it("renders compliance references", () => {
    render(
      <RemediationDetail item={mockItems[0]} />,
    );
    expect(
      screen.getByText("CIS AWS"),
    ).toBeInTheDocument();
  });

  it("renders tab buttons", () => {
    render(
      <RemediationDetail item={mockItems[0]} />,
    );
    expect(
      screen.getByText("Console"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("CLI"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Terraform"),
    ).toBeInTheDocument();
  });
});

describe("ExecutePanel", () => {
  it("renders execute form", () => {
    render(
      <Wrapper>
        <ExecutePanel remediationId="REM_01" />
      </Wrapper>,
    );
    expect(
      screen.getByText("One-Click Execute"),
    ).toBeInTheDocument();
  });
});

describe("RollbackPanel", () => {
  it("renders rollback form", () => {
    render(
      <Wrapper>
        <RollbackPanel remediationId="REM_01" />
      </Wrapper>,
    );
    expect(
      screen.getByRole("button", { name: "Rollback" }),
    ).toBeInTheDocument();
  });
});

describe("AuditTrail", () => {
  it("renders audit entries", () => {
    render(
      <Wrapper>
        <AuditTrail />
      </Wrapper>,
    );
    expect(
      screen.getByText("act-1"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("One-Click"),
    ).toBeInTheDocument();
  });
});

describe("AutoConfigPanel", () => {
  it("renders config entries", () => {
    render(
      <Wrapper>
        <AutoConfigPanel />
      </Wrapper>,
    );
    expect(
      screen.getByText("CHECK_04"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Rollback: 30m/),
    ).toBeInTheDocument();
  });

  it("renders loading state", () => {
    mockConfigState = {
      data: null,
      isLoading: true,
      error: null,
    };
    const { container } = render(
      <Wrapper>
        <AutoConfigPanel />
      </Wrapper>,
    );
    expect(
      container.querySelector(".animate-pulse"),
    ).toBeInTheDocument();
  });

  it("renders error state", () => {
    mockConfigState = {
      data: null,
      isLoading: false,
      error: new Error("fail"),
    };
    render(
      <Wrapper>
        <AutoConfigPanel />
      </Wrapper>,
    );
    expect(
      screen.getByText(
        /Failed to load auto-remediation configs/,
      ),
    ).toBeInTheDocument();
  });

  it("renders empty state", () => {
    mockConfigState = {
      data: { configs: [] },
      isLoading: false,
      error: null,
    };
    render(
      <Wrapper>
        <AutoConfigPanel />
      </Wrapper>,
    );
    expect(
      screen.getByText(
        /No auto-remediation configs configured/,
      ),
    ).toBeInTheDocument();
  });

  it("calls toggle on button click", async () => {
    const user = userEvent.setup();
    render(
      <Wrapper>
        <AutoConfigPanel />
      </Wrapper>,
    );

    const toggleBtn = screen.getByRole("button");
    await user.click(toggleBtn);
    expect(mockSaveConfigMutate).toHaveBeenCalledWith({
      check_id: "CHECK_04",
      enabled: false,
    });
  });

  it("shows approved_by and notify info", () => {
    render(
      <Wrapper>
        <AutoConfigPanel />
      </Wrapper>,
    );
    expect(
      screen.getByText(/Approved by: admin/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Notify: Yes/),
    ).toBeInTheDocument();
  });
});

describe("ExecutePanel interactions", () => {
  it("disables execute when no ARN", () => {
    render(
      <Wrapper>
        <ExecutePanel remediationId="REM_01" />
      </Wrapper>,
    );
    const btn = screen.getByRole("button", {
      name: /Execute Remediation/,
    });
    expect(btn).toBeDisabled();
  });

  it("enables execute when ARN + confirm", async () => {
    const user = userEvent.setup();
    render(
      <Wrapper>
        <ExecutePanel remediationId="REM_01" />
      </Wrapper>,
    );

    await user.type(
      screen.getByPlaceholderText(
        "arn:aws:s3:::my-bucket",
      ),
      "arn:aws:s3:::test",
    );
    await user.click(
      screen.getByRole("checkbox"),
    );

    const btn = screen.getByRole("button", {
      name: /Execute Remediation/,
    });
    expect(btn).not.toBeDisabled();
  });

  it("calls mutate on execute", async () => {
    const user = userEvent.setup();
    render(
      <Wrapper>
        <ExecutePanel remediationId="REM_01" />
      </Wrapper>,
    );

    await user.type(
      screen.getByPlaceholderText(
        "arn:aws:s3:::my-bucket",
      ),
      "arn:aws:s3:::bucket",
    );
    await user.click(screen.getByRole("checkbox"));
    await user.click(
      screen.getByRole("button", {
        name: /Execute Remediation/,
      }),
    );

    expect(mockExecuteMutate).toHaveBeenCalledWith({
      id: "REM_01",
      request: {
        resource_arn: "arn:aws:s3:::bucket",
        confirm: true,
      },
    });
  });

  it("shows pending state", () => {
    mockExecuteState = {
      ...mockExecuteState,
      isPending: true,
    };
    render(
      <Wrapper>
        <ExecutePanel remediationId="REM_01" />
      </Wrapper>,
    );
    expect(
      screen.getByText("Executing..."),
    ).toBeInTheDocument();
  });

  it("shows success result", () => {
    mockExecuteState = {
      ...mockExecuteState,
      isSuccess: true,
      data: {
        action_id: "act-1",
        status: "success",
        rollback_available_until:
          "2026-01-02T00:00:00Z",
      },
    };
    render(
      <Wrapper>
        <ExecutePanel remediationId="REM_01" />
      </Wrapper>,
    );
    expect(
      screen.getByText(/Status: success/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Action ID: act-1/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Rollback available until/),
    ).toBeInTheDocument();
  });

  it("shows error result", () => {
    mockExecuteState = {
      ...mockExecuteState,
      isError: true,
      error: { message: "Access denied" },
    };
    render(
      <Wrapper>
        <ExecutePanel remediationId="REM_01" />
      </Wrapper>,
    );
    expect(
      screen.getByText("Access denied"),
    ).toBeInTheDocument();
  });
});

describe("RollbackPanel interactions", () => {
  it("disables rollback when no action ID", () => {
    render(
      <Wrapper>
        <RollbackPanel remediationId="REM_01" />
      </Wrapper>,
    );
    const btn = screen.getByRole("button", {
      name: /Rollback/,
    });
    expect(btn).toBeDisabled();
  });

  it("calls mutate on rollback", async () => {
    const user = userEvent.setup();
    render(
      <Wrapper>
        <RollbackPanel remediationId="REM_01" />
      </Wrapper>,
    );

    await user.type(
      screen.getByPlaceholderText(
        "Action ID from execution",
      ),
      "act-1",
    );
    await user.click(
      screen.getByRole("button", {
        name: /Rollback/,
      }),
    );

    expect(mockRollbackMutate).toHaveBeenCalledWith({
      id: "REM_01",
      request: { action_id: "act-1" },
    });
  });

  it("shows pending state", () => {
    mockRollbackState = {
      ...mockRollbackState,
      isPending: true,
    };
    render(
      <Wrapper>
        <RollbackPanel remediationId="REM_01" />
      </Wrapper>,
    );
    expect(
      screen.getByText("Rolling back..."),
    ).toBeInTheDocument();
  });

  it("shows success result", () => {
    mockRollbackState = {
      ...mockRollbackState,
      isSuccess: true,
      data: {
        status: "rolled_back",
        message: "Done",
      },
    };
    render(
      <Wrapper>
        <RollbackPanel remediationId="REM_01" />
      </Wrapper>,
    );
    expect(
      screen.getByText(/rolled_back: Done/),
    ).toBeInTheDocument();
  });

  it("shows error result", () => {
    mockRollbackState = {
      ...mockRollbackState,
      isError: true,
      error: { message: "Window expired" },
    };
    render(
      <Wrapper>
        <RollbackPanel remediationId="REM_01" />
      </Wrapper>,
    );
    expect(
      screen.getByText("Window expired"),
    ).toBeInTheDocument();
  });
});

describe("AuditTrail states", () => {
  it("renders loading state", () => {
    mockAuditState = {
      data: null,
      isLoading: true,
      error: null,
    };
    const { container } = render(
      <Wrapper>
        <AuditTrail />
      </Wrapper>,
    );
    expect(
      container.querySelector(".animate-pulse"),
    ).toBeInTheDocument();
  });

  it("renders error state", () => {
    mockAuditState = {
      data: null,
      isLoading: false,
      error: new Error("fail"),
    };
    render(
      <Wrapper>
        <AuditTrail />
      </Wrapper>,
    );
    expect(
      screen.getByText(/Failed to load audit trail/),
    ).toBeInTheDocument();
  });

  it("renders empty state", () => {
    mockAuditState = {
      data: { entries: [] },
      isLoading: false,
      error: null,
    };
    render(
      <Wrapper>
        <AuditTrail />
      </Wrapper>,
    );
    expect(
      screen.getByText(/No audit entries yet/),
    ).toBeInTheDocument();
  });
});
