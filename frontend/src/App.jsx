// Routes: "/" shows the checker; any other path shows the not-found page.
import { Routes, Route, Link } from "react-router-dom";
import Checker from "./Checker";

function NotFound() {
  return (
    <main>
      <h1>Page not found</h1>
      <p>That page doesn't exist.</p>
      <Link to="/">Back to the checker</Link>
    </main>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Checker />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
