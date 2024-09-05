import { ApiUrls } from "../types/data-types";

export const API_URLS: ApiUrls = {
  getQrCode: {
    method: "GET",
    buildURL: (): `/${string}` => "/authorization-request",
  },
};
