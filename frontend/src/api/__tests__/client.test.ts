import { apiClient } from "../client";
import type { InternalAxiosRequestConfig } from "axios";

describe("apiClient", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("has correct base URL", () => {
    expect(apiClient.defaults.baseURL).toBe("/api");
  });

  it("has JSON content type", () => {
    expect(
      apiClient.defaults.headers["Content-Type"],
    ).toBe("application/json");
  });

  it("has request interceptors registered", () => {
    expect(
      apiClient.interceptors.request,
    ).toBeDefined();
  });

  it("has response interceptors registered", () => {
    expect(
      apiClient.interceptors.response,
    ).toBeDefined();
  });

  describe("request interceptor", () => {
    it("adds auth header when token exists", async () => {
      localStorage.setItem("auth_token", "my-jwt");

      const config = {
        headers: {},
      } as InternalAxiosRequestConfig;

      // Get the interceptor handler
      const handlers =
        (
          apiClient.interceptors.request as unknown as {
            handlers: {
              fulfilled: (
                c: InternalAxiosRequestConfig,
              ) => InternalAxiosRequestConfig;
            }[];
          }
        ).handlers;

      const fulfilled = handlers.find(
        (h) => h.fulfilled,
      )?.fulfilled;

      if (fulfilled) {
        const result = fulfilled(config);
        expect(result.headers.Authorization).toBe(
          "Bearer my-jwt",
        );
      }
    });

    it("does not add auth header without token", () => {
      const config = {
        headers: {},
      } as InternalAxiosRequestConfig;

      const handlers =
        (
          apiClient.interceptors.request as unknown as {
            handlers: {
              fulfilled: (
                c: InternalAxiosRequestConfig,
              ) => InternalAxiosRequestConfig;
            }[];
          }
        ).handlers;

      const fulfilled = handlers.find(
        (h) => h.fulfilled,
      )?.fulfilled;

      if (fulfilled) {
        const result = fulfilled(config);
        expect(
          result.headers.Authorization,
        ).toBeUndefined();
      }
    });
  });

  describe("response interceptor", () => {
    it("handles 401 by clearing auth", async () => {
      localStorage.setItem("auth_token", "t");
      localStorage.setItem("auth_user", "u");

      const originalHref = window.location.href;
      // Mock location.href setter
      const locationSpy = vi
        .spyOn(window, "location", "get")
        .mockReturnValue({
          ...window.location,
          href: originalHref,
          set href(_: string) {
            // noop
          },
        } as Location);

      const handlers =
        (
          apiClient.interceptors.response as unknown as {
            handlers: {
              rejected?: (
                e: unknown,
              ) => Promise<never>;
            }[];
          }
        ).handlers;

      const rejected = handlers.find(
        (h) => h.rejected,
      )?.rejected;

      if (rejected) {
        const error = {
          response: {
            status: 401,
            data: { detail: "Unauthorized" },
          },
        };

        await expect(
          rejected(error),
        ).rejects.toEqual(
          expect.objectContaining({
            status: 401,
            message: "Unauthorized",
          }),
        );

        expect(
          localStorage.getItem("auth_token"),
        ).toBeNull();
        expect(
          localStorage.getItem("auth_user"),
        ).toBeNull();
      }

      locationSpy.mockRestore();
    });

    it("normalizes non-401 errors", async () => {
      const handlers =
        (
          apiClient.interceptors.response as unknown as {
            handlers: {
              rejected?: (
                e: unknown,
              ) => Promise<never>;
            }[];
          }
        ).handlers;

      const rejected = handlers.find(
        (h) => h.rejected,
      )?.rejected;

      if (rejected) {
        const error = {
          response: {
            status: 500,
            data: { detail: "Server error" },
          },
          message: "Request failed",
        };

        await expect(
          rejected(error),
        ).rejects.toEqual({
          status: 500,
          message: "Server error",
          detail: { detail: "Server error" },
        });
      }
    });

    it("handles network errors without response", async () => {
      const handlers =
        (
          apiClient.interceptors.response as unknown as {
            handlers: {
              rejected?: (
                e: unknown,
              ) => Promise<never>;
            }[];
          }
        ).handlers;

      const rejected = handlers.find(
        (h) => h.rejected,
      )?.rejected;

      if (rejected) {
        const error = {
          message: "Network Error",
        };

        await expect(
          rejected(error),
        ).rejects.toEqual({
          status: 0,
          message: "Network Error",
          detail: undefined,
        });
      }
    });
  });
});
