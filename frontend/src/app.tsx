// frontend/src/App.tsx
import React, { useState, useMemo, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./components/ui/card";
import { Button } from "./components/ui/button";
import {
  Search,
  Plus,
  Play,
  Square,
  Eye,
  Trash2,
  RotateCcw,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Globe,
  BarChart3,
  TrendingUp,
  AlertCircle,
  CheckCircle,
  Lock,
  Loader2,
  PieChart,
  Link2,
  Hash,
} from "lucide-react";
import {
  PieChart as RechartsPieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";
import ApiService, {
  URLResponse,
  URLDetailResponse,
  BrokenLink,
} from "./services/api";

interface CrawlResult {
  id: number;
  url: string;
  title: string;
  status: "queued" | "running" | "completed" | "error";
  htmlVersion: string;
  internalLinks: number;
  externalLinks: number;
  brokenLinks: number;
  hasLoginForm: boolean;
  createdAt: string;
  headingCounts: {
    h1: number;
    h2: number;
    h3: number;
    h4: number;
    h5: number;
    h6: number;
  };
  errorMessage?: string;
}

const transformBackendData = (data: URLResponse): CrawlResult => ({
  id: data.id,
  url: data.url,
  title: data.title || "Untitled",
  status: data.status === "done" ? "completed" : data.status,
  htmlVersion: data.html_version || "",
  internalLinks: data.internal_links || 0,
  externalLinks: data.external_links || 0,
  brokenLinks: data.inaccessible_links || 0,
  hasLoginForm: data.has_login_form || false,
  createdAt: data.created_at,
  headingCounts: {
    h1: data.h1_count || 0,
    h2: data.h2_count || 0,
    h3: data.h3_count || 0,
    h4: data.h4_count || 0,
    h5: data.h5_count || 0,
    h6: data.h6_count || 0,
  },
  errorMessage: data.error_message,
});

// Login Form
const LoginForm = ({ onLogin }: { onLogin: () => void }) => {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("password");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    try {
      await ApiService.login(username, password);
      onLogin();
    } catch (error) {
      setError(error instanceof Error ? error.message : "Login failed");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex items-center justify-center">
      <Card className="w-full max-w-md shadow-lg">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <Lock className="h-12 w-12 text-blue-600" />
          </div>
          <CardTitle className="text-2xl">Web Crawler Task</CardTitle>
          <CardDescription>
            Pseudo login form for the web crawler task.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={isLoading}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={isLoading}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            {error && <p className="text-sm text-red-500">{error}</p>}
            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Logging in...
                </>
              ) : (
                "Login"
              )}
            </Button>
          </form>
          <div className="mt-4 text-sm text-gray-600 text-center">
            <p>User credentials:</p>
            <p>
              <strong>Username:</strong> admin
            </p>
            <p>
              <strong>Password:</strong> password
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [crawlResults, setCrawlResults] = useState<CrawlResult[]>([]);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<keyof CrawlResult>("createdAt");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalResults, setTotalResults] = useState(0);
  const [newUrl, setNewUrl] = useState("");
  const [currentView, setCurrentView] = useState<"dashboard" | "detail">(
    "dashboard"
  );
  const [selectedResult, setSelectedResult] = useState<CrawlResult | null>(
    null
  );
  const [selectedResultDetail, setSelectedResultDetail] =
    useState<URLDetailResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isUrlLoading, setIsUrlLoading] = useState(false);

  const itemsPerPage = 10;

  // Check authentication status on mount
  useEffect(() => {
    const token = ApiService.getToken();
    if (token) {
      setIsAuthenticated(true);
    }
    setIsCheckingAuth(false);
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      fetchUrls();
      const interval = setInterval(fetchUrls, 5000);
      return () => clearInterval(interval);
    }
  }, [
    isAuthenticated,
    currentPage,
    searchTerm,
    statusFilter,
    sortBy,
    sortOrder,
  ]);

  const fetchUrls = async () => {
    try {
      const response = await ApiService.getUrls({
        page: currentPage,
        page_size: itemsPerPage,
        sort: sortBy === "createdAt" ? "created_at" : sortBy,
        order: sortOrder,
        search: searchTerm || undefined,
        filter: statusFilter !== "all" ? statusFilter : undefined,
      });
      const transformedData = response.data.map(transformBackendData);
      setCrawlResults(transformedData);
      setTotalResults(response.total);
      setTotalPages(response.total_pages);
    } catch (error) {
      console.error("Failed to fetch URLs:", error);
      if (
        !(error instanceof Error && error.message.includes("Authentication"))
      ) {
        // Empty statement
      }
    }
  };

  const handleLogin = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    ApiService.clearToken();
    setIsAuthenticated(false);
    setCrawlResults([]);
    setSelectedResult(null);
    setCurrentView("dashboard");
  };

  const handleAddUrl = async () => {
    if (!newUrl.trim()) return;

    setIsUrlLoading(true);
    try {
      console.log("Adding URL:", newUrl);
      const response = await ApiService.addUrl(newUrl);
      console.log("URL added:", response);
      setNewUrl("");
      // Start crawling immediately after adding
      if (response && response.id) {
        setTimeout(async () => {
          try {
            console.log("Starting crawl for ID:", response.id);
            await ApiService.startCrawling(response.id);
            fetchUrls();
          } catch (error) {
            console.error("Failed to start crawling:", error);
          }
        }, 1000);
      }
      fetchUrls();
    } catch (error) {
      console.error("Failed to add URL:", error);
      alert(
        "Failed to add URL: " +
          (error instanceof Error ? error.message : "Unknown error")
      );
    } finally {
      setIsUrlLoading(false);
    }
  };

  const handleStartCrawl = async (id: number) => {
    try {
      await ApiService.startCrawling(id);
      fetchUrls();
    } catch (error) {
      console.error("Failed to start crawling:", error);
    }
  };

  const handleStopCrawl = async (id: number) => {
    try {
      await ApiService.stopCrawling(id);
      fetchUrls();
    } catch (error) {
      console.error("Failed to stop crawling:", error);
    }
  };

  const handleBulkAction = async (action: "delete" | "rerun") => {
    if (selectedIds.length === 0) return;

    try {
      await ApiService.bulkAction(selectedIds, action);
      setSelectedIds([]);
      fetchUrls();
    } catch (error) {
      console.error(`Failed to ${action} URLs:`, error);
    }
  };

  const handleViewDetails = async (result: CrawlResult) => {
    try {
      setIsLoading(true);
      const detailResponse = await ApiService.getUrlDetails(result.id);
      setSelectedResult(result);
      setSelectedResultDetail(detailResponse);
      setCurrentView("detail");
    } catch (error) {
      console.error("Failed to fetch URL details:", error);
      setSelectedResult(result);
      setSelectedResultDetail(null);
      setCurrentView("detail");
    } finally {
      setIsLoading(false);
    }
  };

  const filteredAndSortedResults = crawlResults;
  const paginatedResults = filteredAndSortedResults;

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedIds(paginatedResults.map((result) => result.id));
    } else {
      setSelectedIds([]);
    }
  };

  const handleSelectResult = (id: number, checked: boolean) => {
    if (checked) {
      setSelectedIds((prev) => [...prev, id]);
    } else {
      setSelectedIds((prev) => prev.filter((selectedId) => selectedId !== id));
    }
  };

  const handleSort = (column: keyof CrawlResult) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(column);
      setSortOrder("asc");
    }
  };

  const getStatusBadge = (status: CrawlResult["status"]) => {
    const statusConfig = {
      queued: { label: "Queued", className: "bg-yellow-100 text-yellow-800" },
      running: { label: "Running", className: "bg-blue-100 text-blue-800" },
      completed: {
        label: "Completed",
        className: "bg-green-100 text-green-800",
      },
      error: { label: "Error", className: "bg-red-100 text-red-800" },
    };

    const config = statusConfig[status];
    return (
      <span
        className={`px-2 py-1 rounded-md text-xs font-medium ${config.className}`}
      >
        {config.label}
      </span>
    );
  };

  const handleBackToDashboard = () => {
    setSelectedResult(null);
    setSelectedResultDetail(null);
    setCurrentView("dashboard");
  };

  const stats = {
    total: totalResults,
    completed: crawlResults.filter((r) => r.status === "completed").length,
    running: crawlResults.filter((r) => r.status === "running").length,
    errors: crawlResults.filter((r) => r.status === "error").length,
  };

  if (isCheckingAuth) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-12 w-12 text-blue-600 mx-auto mb-4 animate-spin" />
          <p className="text-slate-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginForm onLogin={handleLogin} />;
  }

  if (currentView === "detail" && selectedResult) {
    const brokenLinks = selectedResultDetail?.broken_links || [];
    const linkDistributionData = [
      {
        name: "Internal Links",
        value: selectedResult.internalLinks,
        color: "#3b82f6",
      },
      {
        name: "External Links",
        value: selectedResult.externalLinks,
        color: "#10b981",
      },
      {
        name: "Broken Links",
        value: brokenLinks.length,
        color: "#ef4444",
      },
    ].filter((item) => item.value > 0);

    const headingData = [
      {
        heading: "H1",
        count: selectedResult.headingCounts.h1,
        color: "#8b5cf6",
      },
      {
        heading: "H2",
        count: selectedResult.headingCounts.h2,
        color: "#06b6d4",
      },
      {
        heading: "H3",
        count: selectedResult.headingCounts.h3,
        color: "#10b981",
      },
      {
        heading: "H4",
        count: selectedResult.headingCounts.h4,
        color: "#f59e0b",
      },
      {
        heading: "H5",
        count: selectedResult.headingCounts.h5,
        color: "#ef4444",
      },
      {
        heading: "H6",
        count: selectedResult.headingCounts.h6,
        color: "#8b5cf6",
      },
    ].filter((item) => item.count > 0);

    // Custom Pie chart tooltip
    const PieTooltip = ({ active, payload }: any) => {
      if (active && payload && payload.length) {
        const data = payload[0];
        const total = linkDistributionData.reduce(
          (sum, item) => sum + item.value,
          0
        );
        const percentage = ((data.value / total) * 100).toFixed(1);
        return (
          <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
            <p className="font-medium">{data.name}</p>
            <p className="text-sm text-gray-600">
              {data.value} links ({percentage}%)
            </p>
          </div>
        );
      }
      return null;
    };

    // Custom Bar chart tooltip
    const BarTooltip = ({ active, payload, label }: any) => {
      if (active && payload && payload.length) {
        return (
          <div className="bg-white p-3 border border-gray-200 rounded-lg shadow-lg">
            <p className="font-medium">{label} Tags</p>
            <p className="text-sm text-gray-600">
              {payload[0].value} occurrences
            </p>
          </div>
        );
      }
      return null;
    };

    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
        <div className="container mx-auto px-4 py-8">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-4">
              <Button variant="outline" onClick={handleBackToDashboard}>
                <ChevronLeft className="mr-2 h-4 w-4" />
                Back to Dashboard
              </Button>
              <div>
                <h2 className="text-2xl font-bold text-slate-800">
                  {selectedResult.title}
                </h2>
                <p className="text-slate-600 flex items-center gap-2">
                  <Link2 className="h-4 w-4" />
                  {selectedResult.url}
                </p>
              </div>
            </div>
            <Button variant="outline" onClick={handleLogout}>
              Logout
            </Button>
          </div>

          {/* Result Summary */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <Card className="border-l-4 border-l-blue-500">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                  <Hash className="h-4 w-4" />
                  HTML Version
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-blue-600">
                  {selectedResult.htmlVersion || "HTML5"}
                </div>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-green-500">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                  <Link2 className="h-4 w-4" />
                  Total Links
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-600">
                  {selectedResult.internalLinks + selectedResult.externalLinks}
                </div>
                <p className="text-xs text-gray-500 mt-1">
                  {selectedResult.internalLinks} internal •{" "}
                  {selectedResult.externalLinks} external
                </p>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-red-500">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                  <AlertCircle className="h-4 w-4" />
                  Broken Links
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-600">
                  {brokenLinks.length}
                </div>
                <p className="text-xs text-gray-500 mt-1">
                  {brokenLinks.length === 0
                    ? "All links working"
                    : "Need attention"}
                </p>
              </CardContent>
            </Card>

            <Card className="border-l-4 border-l-purple-500">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                  <CheckCircle className="h-4 w-4" />
                  Login Form
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-2">
                  {selectedResult.hasLoginForm ? (
                    <>
                      <CheckCircle className="h-5 w-5 text-green-600" />
                      <span className="text-green-600 font-medium">
                        Present
                      </span>
                    </>
                  ) : (
                    <>
                      <AlertCircle className="h-5 w-5 text-gray-400" />
                      <span className="text-gray-600">Not Found</span>
                    </>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <Card className="shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <PieChart className="h-5 w-5 text-blue-600" />
                  Link Distribution
                </CardTitle>
                <CardDescription>
                  Breakdown of internal, external, and broken links
                </CardDescription>
              </CardHeader>
              <CardContent>
                {linkDistributionData.length > 0 ? (
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <RechartsPieChart>
                        <Pie
                          data={linkDistributionData}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={120}
                          paddingAngle={5}
                          dataKey="value"
                        >
                          {linkDistributionData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip content={<PieTooltip />} />
                        <Legend />
                      </RechartsPieChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <div className="h-80 flex items-center justify-center text-gray-500">
                    <div className="text-center">
                      <Link2 className="h-12 w-12 mx-auto mb-2 text-gray-300" />
                      <p>No link data available</p>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BarChart3 className="h-5 w-5 text-purple-600" />
                  Heading Structure
                </CardTitle>
                <CardDescription>
                  Distribution of heading tags (H1-H6) across the page
                </CardDescription>
              </CardHeader>
              <CardContent>
                {headingData.length > 0 ? (
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={headingData}
                        margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                        <XAxis dataKey="heading" stroke="#666" fontSize={12} />
                        <YAxis stroke="#666" fontSize={12} />
                        <Tooltip content={<BarTooltip />} />
                        <Bar
                          dataKey="count"
                          radius={[4, 4, 0, 0]}
                          fill="#8b5cf6"
                        >
                          {headingData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <div className="h-80 flex items-center justify-center text-gray-500">
                    <div className="text-center">
                      <Hash className="h-12 w-12 mx-auto mb-2 text-gray-300" />
                      <p>No heading data available</p>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {headingData.length > 0 && (
            <Card className="shadow-lg mb-6">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Hash className="h-5 w-5 text-indigo-600" />
                  Detailed Heading Analysis
                </CardTitle>
                <CardDescription>
                  SEO and accessibility insights for your heading structure
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
                  {Object.entries(selectedResult.headingCounts).map(
                    ([level, count]) => (
                      <div
                        key={level}
                        className="text-center p-4 bg-gray-50 rounded-lg"
                      >
                        <div className="text-2xl font-bold text-gray-700 mb-1">
                          {count}
                        </div>
                        <div className="text-sm font-medium text-gray-600 uppercase">
                          {level}
                        </div>
                        <div
                          className={`w-full h-2 rounded-full mt-2 ${
                            count > 0
                              ? "bg-gradient-to-r from-blue-400 to-purple-500"
                              : "bg-gray-200"
                          }`}
                        />
                      </div>
                    )
                  )}
                </div>

                <div className="mt-6 p-4 bg-blue-50 rounded-lg">
                  <h4 className="font-semibold text-blue-800 mb-2">
                    SEO Insights:
                  </h4>
                  <div className="space-y-1 text-sm text-blue-700">
                    {selectedResult.headingCounts.h1 === 0 && (
                      <p>
                        ⚠️ Missing H1 tag - Important for SEO and accessibility
                      </p>
                    )}
                    {selectedResult.headingCounts.h1 > 1 && (
                      <p>
                        ⚠️ Multiple H1 tags found - Consider using only one H1
                        per page
                      </p>
                    )}
                    {selectedResult.headingCounts.h1 === 1 && (
                      <p>✅ Good: Single H1 tag found</p>
                    )}
                    {Object.values(selectedResult.headingCounts).some(
                      (count) => count > 0
                    ) ? (
                      <p>
                        ✅ Heading structure present - Good for content
                        hierarchy
                      </p>
                    ) : (
                      <p>
                        ⚠️ No headings found - Consider adding headings for
                        better structure
                      </p>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {brokenLinks.length > 0 && (
            <Card className="shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertCircle className="h-5 w-5 text-red-600" />
                  Broken Links ({brokenLinks.length})
                </CardTitle>
                <CardDescription>
                  Links that returned error status codes and need attention
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 max-h-96 overflow-y-auto">
                  {brokenLinks.map((link, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-4 bg-red-50 rounded-lg border border-red-100 hover:bg-red-100 transition-colors"
                    >
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <span
                          className={`px-3 py-1 rounded-full text-white text-xs font-bold ${
                            link.status_code >= 500
                              ? "bg-red-600"
                              : link.status_code >= 400
                              ? "bg-orange-500"
                              : "bg-gray-500"
                          }`}
                        >
                          {link.status_code}
                        </span>
                        <span className="text-sm font-mono truncate text-gray-700">
                          {link.link_url}
                        </span>
                      </div>
                      <div className="text-xs text-gray-500 ml-2">
                        {link.status_code >= 500
                          ? "Server Error"
                          : link.status_code >= 400
                          ? "Client Error"
                          : "Unknown"}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100">
      <div className="container mx-auto px-4 py-8">
        <div className="mb-8 flex justify-between items-start">
          <div>
            <h1 className="text-4xl font-bold text-slate-800 mb-2">
              Web Crawler Assignment
            </h1>
          </div>
          <Button variant="outline" onClick={handleLogout}>
            Logout
          </Button>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                <Globe className="h-4 w-4" />
                Total URLs
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-600" />
                Completed
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">
                {stats.completed}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-blue-600" />
                Running
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">
                {stats.running}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-gray-600 flex items-center gap-2">
                <AlertCircle className="h-4 w-4 text-red-600" />
                Errors
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">
                {stats.errors}
              </div>
            </CardContent>
          </Card>
        </div>

        <Card className="shadow-lg border-0 bg-white mb-6">
          <CardHeader className="pb-4">
            <CardTitle className="flex items-center gap-2 text-xl">
              <Globe className="h-5 w-5 text-blue-600" />
              Add Website for Analysis
            </CardTitle>
            <CardDescription>
              Enter a website URL to crawl and analyze its content.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-3">
              <input
                type="url"
                placeholder="https://example.com"
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && handleAddUrl()}
                disabled={isUrlLoading}
                className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <Button onClick={handleAddUrl} disabled={isUrlLoading}>
                {isUrlLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Adding...
                  </>
                ) : (
                  <>
                    <Plus className="mr-2 h-4 w-4" />
                    Analyze
                  </>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="shadow-lg border-0 bg-white">
          <CardHeader className="pb-4">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <CardTitle className="text-xl">Analysis Results</CardTitle>
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
                  <input
                    placeholder="Search URLs or titles..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 pr-3 py-2 border border-gray-300 rounded-md w-64 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>

                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 w-40"
                >
                  <option value="all">All Status</option>
                  <option value="queued">Queued</option>
                  <option value="running">Running</option>
                  <option value="done">Completed</option>
                  <option value="error">Error</option>
                </select>
              </div>
            </div>

            {/* Bulk Actions */}
            {selectedIds.length > 0 && (
              <div className="flex items-center gap-2 mt-4 p-3 bg-blue-50 rounded-lg">
                <span className="text-sm text-blue-700">
                  {selectedIds.length} item(s) selected
                </span>
                <Button
                  size="sm"
                  variant="outline"
                  className="ml-auto"
                  onClick={() => handleBulkAction("rerun")}
                >
                  <RotateCcw className="mr-2 h-4 w-4" />
                  Re-run
                </Button>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => handleBulkAction("delete")}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Delete
                </Button>
              </div>
            )}
          </CardHeader>

          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200">
                    <th className="text-left p-3">
                      <input
                        type="checkbox"
                        checked={
                          selectedIds.length === paginatedResults.length &&
                          paginatedResults.length > 0
                        }
                        onChange={(e) => handleSelectAll(e.target.checked)}
                        className="rounded border-gray-300"
                      />
                    </th>
                    <th className="text-left p-3">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleSort("url")}
                        className="font-semibold"
                      >
                        URL <ArrowUpDown className="ml-1 h-4 w-4" />
                      </Button>
                    </th>
                    <th className="text-left p-3">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleSort("title")}
                        className="font-semibold"
                      >
                        Title <ArrowUpDown className="ml-1 h-4 w-4" />
                      </Button>
                    </th>
                    <th className="text-left p-3">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleSort("htmlVersion")}
                        className="font-semibold"
                      >
                        HTML Version <ArrowUpDown className="ml-1 h-4 w-4" />
                      </Button>
                    </th>
                    <th className="text-left p-3">Internal Links</th>
                    <th className="text-left p-3">External Links</th>
                    <th className="text-left p-3">Status</th>
                    <th className="text-left p-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedResults.map((result) => (
                    <tr
                      key={result.id}
                      className="border-b border-gray-100 hover:bg-gray-50"
                    >
                      <td className="p-3">
                        <input
                          type="checkbox"
                          checked={selectedIds.includes(result.id)}
                          onChange={(e) =>
                            handleSelectResult(result.id, e.target.checked)
                          }
                          className="rounded border-gray-300"
                        />
                      </td>
                      <td className="p-3">
                        <div className="max-w-xs truncate text-blue-600">
                          {result.url}
                        </div>
                      </td>
                      <td className="p-3">
                        <div className="max-w-xs truncate font-medium">
                          {result.title || "Untitled"}
                        </div>
                      </td>
                      <td className="p-3">{result.htmlVersion || "-"}</td>
                      <td className="p-3">{result.internalLinks}</td>
                      <td className="p-3">{result.externalLinks}</td>
                      <td className="p-3">{getStatusBadge(result.status)}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          {result.status === "queued" && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleStartCrawl(result.id)}
                            >
                              <Play className="h-4 w-4" />
                            </Button>
                          )}
                          {result.status === "running" && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleStopCrawl(result.id)}
                            >
                              <Square className="h-4 w-4" />
                            </Button>
                          )}
                          {result.status === "completed" && (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleViewDetails(result)}
                              disabled={isLoading}
                            >
                              {isLoading ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <Eye className="h-4 w-4" />
                              )}
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4">
                <div className="text-sm text-gray-600">
                  Showing page {currentPage} of {totalPages} ({totalResults}{" "}
                  total results)
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      setCurrentPage((prev) => Math.max(1, prev - 1))
                    }
                    disabled={currentPage === 1}
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </Button>
                  <span className="text-sm">
                    Page {currentPage} of {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      setCurrentPage((prev) => Math.min(totalPages, prev + 1))
                    }
                    disabled={currentPage === totalPages}
                  >
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}

            {filteredAndSortedResults.length === 0 && (
              <div className="text-center py-8 text-gray-500">
                {crawlResults.length === 0
                  ? "No URLs analyzed yet"
                  : "No results match your filters"}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default App;
