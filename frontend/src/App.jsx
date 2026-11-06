import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import About from "./pages/About";
import Dashboard from "./pages/Dashboard";
import History from "./pages/History";
import Performance from "./pages/Performance";
import Results from "./pages/Results";
import TrafficAnalysis from "./pages/TrafficAnalysis";
import Upload from "./pages/Upload";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="analyze" element={<TrafficAnalysis />} />
        <Route path="upload" element={<Upload />} />
        <Route path="results" element={<Results />} />
        <Route path="results/:id" element={<Results />} />
        <Route path="performance" element={<Performance />} />
        <Route path="alerts" element={<History />} />
        <Route path="about" element={<About />} />
      </Route>
    </Routes>
  );
}
