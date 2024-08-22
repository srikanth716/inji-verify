import { createSlice } from "@reduxjs/toolkit";
import { AlertInfo } from "../../../types/data-types";

export const InitialState: AlertInfo = {};

const alertsSlice = createSlice({
  name: "Alerts",
  initialState: InitialState,
  reducers: {
    raiseAlert: (state, action) => {
      state.open = true;
      state.severity = action.payload.severity;
      state.message = action.payload.message;
      state.autoHideDuration = action.payload.autoHideDuration ?? 5000;
    },
    closeAlert: (state, action) => {
      state.open = false;
    },
  },
});

export const { raiseAlert, closeAlert } = alertsSlice.actions;

export default alertsSlice.reducer;
