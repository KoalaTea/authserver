import { gql, useQuery } from "@apollo/client";

const query = gql`
    query GetUsers {
        users {
            edges {
                node {
                    id
                    name
                }
            }
        }
    }
`

export const UserList = () => {

    // const { loading, error, data } = useQuery(query);
    const { data } = useQuery(query);


    return (
        <>
            <p>Testing 123</p>
            <div>
                {data?.users?.edges?.map((edge: any) => {
                    const item = edge.node;
                    return <div key={item?.id}>{item?.name}</div>
                })}
            </div>
        </>
    );
}