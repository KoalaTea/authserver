import './App.css';
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { UserList } from "./pages/user-list"

const router = createBrowserRouter([
  {
    path: "/",
    element: <UserList />,
  }
])

function App() {
  return (
    <RouterProvider router={router} />
  );
}

export default App;
