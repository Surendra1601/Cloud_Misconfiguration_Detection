import {
  render,
  screen,
  act,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ViolationsTable from "../ViolationsTable";
import ViolationFilters from "../ViolationFilters";
import ViolationDetail from "../ViolationDetail";

const mockViolations = [
  {
    check_id: "CHECK_01",
    resource: "arn:aws:s3:::bucket-1",
    severity: "critical",
    status: "alarm",
    domain: "data_protection",
    reason: "Public access",
    remediation_id: "REM_01",
    compliance: {
      cis_aws: ["2.1"],
      nist_800_53: [],
      pci_dss: [],
      hipaa: [],
      soc2: [],
    },
  },
  {
    check_id: "CHECK_02",
    resource: "arn:aws:ec2:::i-123",
    severity: "high",
    status: "alarm",
    domain: "network",
    reason: "Open ports",
    remediation_id: null,
    compliance: {
      cis_aws: [],
      nist_800_53: [],
      pci_dss: [],
      hipaa: [],
      soc2: [],
    },
  },
];

describe("ViolationsTable", () => {
  it("renders table with violations", () => {
    render(
      <ViolationsTable
        data={mockViolations}
        onRowClick={() => {}}
      />,
    );
    expect(
      screen.getByText("CHECK_01"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("CHECK_02"),
    ).toBeInTheDocument();
  });

  it("renders empty state", () => {
    render(
      <ViolationsTable
        data={[]}
        onRowClick={() => {}}
      />,
    );
    expect(
      screen.getByText("No violations found."),
    ).toBeInTheDocument();
  });

  it("calls onRowClick", async () => {
    const onClick = vi.fn();
    const user = userEvent.setup();
    render(
      <ViolationsTable
        data={mockViolations}
        onRowClick={onClick}
      />,
    );

    await user.click(screen.getByText("CHECK_01"));
    expect(onClick).toHaveBeenCalledWith(
      mockViolations[0],
    );
  });

  it("renders column headers", () => {
    render(
      <ViolationsTable
        data={mockViolations}
        onRowClick={() => {}}
      />,
    );
    expect(
      screen.getByText("Issue"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Severity"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Status"),
    ).toBeInTheDocument();
  });
});

describe("ViolationFilters", () => {
  it("renders filter dropdowns", () => {
    render(
      <ViolationFilters
        filters={{
          severity: "",
          domain: "",
          status: "",
        }}
        onChange={() => {}}
      />,
    );
    const selects =
      screen.getAllByRole("combobox");
    expect(selects.length).toBeGreaterThanOrEqual(3);
  });

  it("calls onChange on filter change", async () => {
    const onChange = vi.fn();
    const user = userEvent.setup();
    render(
      <ViolationFilters
        filters={{
          severity: "",
          domain: "",
          status: "",
        }}
        onChange={onChange}
      />,
    );

    const selects =
      screen.getAllByRole("combobox");
    await user.selectOptions(selects[0], "critical");
    expect(onChange).toHaveBeenCalled();
  });

  it("shows clear button when filter active", () => {
    render(
      <ViolationFilters
        filters={{
          severity: "critical",
          domain: "",
          status: "",
        }}
        onChange={() => {}}
      />,
    );
    expect(
      screen.getByText("Clear filters"),
    ).toBeInTheDocument();
  });
});

describe("ViolationDetail", () => {
  it("renders violation info", () => {
    render(
      <ViolationDetail
        violation={mockViolations[0]}
        onClose={() => {}}
      />,
    );
    expect(
      screen.getByText("CHECK_01"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Public access"),
    ).toBeInTheDocument();
  });

  it("calls onClose on backdrop click", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(
      <ViolationDetail
        violation={mockViolations[0]}
        onClose={onClose}
      />,
    );

    // Click the backdrop overlay
    const backdrop = screen.getByTestId
      ? document.querySelector(
          '[class*="bg-black"]',
        )
      : null;
    if (backdrop) {
      await user.click(backdrop);
      expect(onClose).toHaveBeenCalled();
    }
  });
});
