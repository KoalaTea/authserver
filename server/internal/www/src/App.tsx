
import './App.css'
import { ExamplePage } from './pages/example';
import { UserList } from './pages/user-list';
import { InactiveUserList } from './pages/inactive-user-list';
import { createBrowserRouter, RouterProvider } from "react-router";
// Import styles of packages that you've installed.
// All packages except `@mantine/hooks` require styles imports
import '@mantine/core/styles.css';

import { MantineProvider } from '@mantine/core';
import { AuthorizationContextProvider } from './context/AuthorizationContext';

const router = createBrowserRouter([
  {
    path: "/",
    element: <ExamplePage />,
  },
  {
    path: "/users/",
    element: <UserList />,
  },
  {
    path: "/inactive-users/",
    element: <InactiveUserList />,
  }
  // ])
], { basename: "/www" })

function App() {


  return (
    <MantineProvider>
      <AuthorizationContextProvider>
        <RouterProvider router={router} />
      </AuthorizationContextProvider>
    </MantineProvider>
  )
}

export default App
