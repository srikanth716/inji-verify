import { HTTP_METHOD } from "../types/data-types";

export async function request(
  method: HTTP_METHOD,
  path: `/${string}` | string,
  body?: Record<string, unknown>,
  host = window.location.origin,
  headers: Record<string, string> = {
    "Content-Type": "application/json",
  }
) {
  //   let response;
  //   const requestUrl = path.indexOf("https://") !== -1 ? path : host + path;
  try {
    return Promise.resolve({
      data: "openid4vp://authorize?request_uri=https://api.jsonserve.com/DNknuO",
    });
    // const jsonResponse = await response.json();

    // if (response.status >= 400) {
    //   let backendUrl = host + path;
    //   let errorMessage =
    //     jsonResponse.message ||
    //     (typeof jsonResponse.error === "object"
    //       ? JSON.stringify(jsonResponse.error)
    //       : jsonResponse.error);
    //   console.error(
    //     `The backend API ${backendUrl} returned error code ${response.status} with message --> ${errorMessage}`
    //   );
    //   throw new Error(errorMessage);
    // }

    // if (jsonResponse.errors && jsonResponse.errors.length) {
    //   let backendUrl = host + path;
    //   const { errorCode, errorMessage } = jsonResponse.errors.shift();
    //   console.error(
    //     "The backend API " +
    //       backendUrl +
    //       " returned error response --> error code is : " +
    //       errorCode +
    //       " error message is : " +
    //       errorMessage
    //   );
    //   throw new Error(errorCode, errorMessage);
    // }
    // return response;
  } catch (error) {
    console.error(
      `Error occurred while making request: ${host + path}: ${error}`
    );
    throw error;
  }
}
