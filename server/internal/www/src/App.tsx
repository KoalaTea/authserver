import './App.css';
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { UserList } from "./pages/user-list"

const router = createBrowserRouter([
  {
    path: "/",
    element: <UserList />,
  }
], { basename: "/www" })

function App() {
  return (
    <div>
      <RouterProvider router={router} />
      <p>WHAT</p>
    </div>
  );
}

export default App;
