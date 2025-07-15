// frontend/src/services/api.ts
const LOCALHOST_URL = "http://localhost:8080"; // Adjust based on your backend server URL

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  username: string;
}

export interface URLRequest {
  url: string;
}

export interface URLResponse {
  id: number;
  url: string;
  title: string;
  html_version: string;
  status: "queued" | "running" | "done" | "error";
  created_at: string;
  updated_at: string;
  h1_count: number;
  h2_count: number;
  h3_count: number;
  h4_count: number;
  h5_count: number;
  h6_count: number;
  internal_links: number;
  external_links: number;
  inaccessible_links: number;
  has_login_form: boolean;
  error_message: string;
}

export interface URLsResponse {
  data: URLResponse[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface BrokenLink {
  id: number;
  link_url: string;
  status_code: number;
  created_at: string;
}

export interface URLDetailResponse {
  url: URLResponse;
  broken_links: BrokenLink[];
}

export interface BulkActionRequest {
  url_ids: number[];
  action: "delete" | "rerun";
}

class ApiService {
  private token: string | null = null;

  constructor() {
    this.token = localStorage.getItem("auth_token");
  }

  setToken(token: string) {
    this.token = token;
    localStorage.setItem("auth_token", token);
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem("auth_token");
  }

  getToken(): string | null {
    return this.token;
  }

  private getHeaders(): HeadersInit {
    const headers: HeadersInit = {
      "Content-Type": "application/json",
    };

    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    return headers;
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    if (!response.ok) {
      if (response.status === 401) {
        this.clearToken();
        throw new Error("Authentication required");
      }

      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Authentication
  async login(username: string, password: string): Promise<LoginResponse> {
    const response = await fetch(`${LOCALHOST_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const data = await this.handleResponse<LoginResponse>(response);
    if (data.token) {
      this.setToken(data.token);
    }
    return data;
  }

  // URLs Management
  async addUrl(url: string): Promise<URLResponse> {
    const response = await fetch(`${LOCALHOST_URL}/api/urls`, {
      method: "POST",
      headers: this.getHeaders(),
      body: JSON.stringify({ url }),
    });

    return this.handleResponse<URLResponse>(response);
  }

  async getUrls(
    params: {
      page?: number;
      page_size?: number;
      sort?: string;
      order?: "asc" | "desc";
      search?: string;
      filter?: string;
    } = {}
  ): Promise<URLsResponse> {
    const queryParams = new URLSearchParams();

    if (params.page) queryParams.append("page", params.page.toString());
    if (params.page_size)
      queryParams.append("page_size", params.page_size.toString());
    if (params.sort) queryParams.append("sort", params.sort);
    if (params.order) queryParams.append("order", params.order);
    if (params.search) queryParams.append("search", params.search);
    if (params.filter && params.filter !== "all")
      queryParams.append("filter", params.filter);

    const url = `${LOCALHOST_URL}/api/urls${
      queryParams.toString() ? "?" + queryParams.toString() : ""
    }`;
    console.log("Fetching URLs from:", url);

    const response = await fetch(url, {
      headers: this.getHeaders(),
    });

    return this.handleResponse<URLsResponse>(response);
  }

  async getUrlDetails(id: number): Promise<URLDetailResponse> {
    const response = await fetch(`${LOCALHOST_URL}/api/urls/${id}`, {
      headers: this.getHeaders(),
    });

    return this.handleResponse<URLDetailResponse>(response);
  }

  async startCrawling(id: number): Promise<{ message: string }> {
    const response = await fetch(`${LOCALHOST_URL}/api/urls/${id}/start`, {
      method: "POST",
      headers: this.getHeaders(),
    });

    return this.handleResponse<{ message: string }>(response);
  }

  async stopCrawling(id: number): Promise<{ message: string }> {
    const response = await fetch(`${LOCALHOST_URL}/api/urls/${id}/stop`, {
      method: "POST",
      headers: this.getHeaders(),
    });

    return this.handleResponse<{ message: string }>(response);
  }

  async bulkAction(
    urlIds: number[],
    action: "delete" | "rerun"
  ): Promise<{ message: string }> {
    const response = await fetch(`${LOCALHOST_URL}/api/urls/bulk`, {
      method: "POST",
      headers: this.getHeaders(),
      body: JSON.stringify({ url_ids: urlIds, action }),
    });

    return this.handleResponse<{ message: string }>(response);
  }

  // Health check
  async healthCheck(): Promise<{ status: string }> {
    const response = await fetch(`${LOCALHOST_URL}/health`);
    return this.handleResponse<{ status: string }>(response);
  }
}

export default new ApiService();
