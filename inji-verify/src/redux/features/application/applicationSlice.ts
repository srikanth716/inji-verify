import { createSlice } from "@reduxjs/toolkit";
import { ApplicationState } from "../../../types/data-types";

export const PreloadedState: ApplicationState = {
  internetConnectionStatus: "ONLINE",
};

const applicationSlice = createSlice({
  name: "ApplicationState",
  initialState: PreloadedState,
  reducers: {
    updateInternetConnectionStatus: (state, action) => {
      state.internetConnectionStatus = action.payload.internetConnectionStatus;
    },
  },
});

export const { updateInternetConnectionStatus } = applicationSlice.actions;

export default applicationSlice.reducer;
