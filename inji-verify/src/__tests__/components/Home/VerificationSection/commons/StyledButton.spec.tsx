import React from "react";
import { render, screen } from "@testing-library/react";
import Button from "../../../../../components/commons/Button";

describe("Custom Button", () => {
  test("Test rendering", () => {
    render(<Button title="A Custom Button" id={""} />);
    expect(screen.getByText("A Custom Button")).toBeInTheDocument();
  });
});
